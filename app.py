import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import click
from datetime import datetime
from jinja2 import pass_eval_context
from markupsafe import Markup, escape
import uuid
from weasyprint import HTML, CSS # For PDF generation

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DATABASE'] = os.path.join(app.instance_path, 'users.db')
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')
app.config['PAYSLIP_UPLOAD_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'payslips')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}

DEPARTMENT_CHOICES = ["Human Resources", "IT", "Marketing", "Sales", "Operations", "Finance", "Workers"]
GENDER_CHOICES = ["Male", "Female", "Other", "Prefer not to say"]

# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        try:
            os.makedirs(app.instance_path, exist_ok=True)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            os.makedirs(app.config['PAYSLIP_UPLOAD_FOLDER'], exist_ok=True)
        except OSError as e:
            app.logger.error(f"Error creating instance/upload paths: {e}")
        g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db() # Ensures folders are created via get_db if not already
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('init-db')
def init_db_command():
    init_db()
    click.echo('Initialized the database.')

app.teardown_appcontext(close_db)

@app.cli.command('make-admin')
@click.argument('username')
def make_admin_command(username):
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if user is None: click.echo(f"User {username} not found."); return
    db.execute('UPDATE users SET is_admin = 1 WHERE username = ?', (username,)); db.commit()
    click.echo(f"User {username} is now an admin.")

def adapt_datetime_iso(val): return val.isoformat()
def convert_datetime_iso(val):
    if not val: return None
    val_str = val.decode()
    try: return datetime.fromisoformat(val_str)
    except (ValueError, AttributeError):
        try: return datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, AttributeError):
            try: return datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S")
            except (ValueError, AttributeError): app.logger.warning(f"Could not parse datetime: {val_str}"); return None

sqlite3.register_adapter(datetime, adapt_datetime_iso)
sqlite3.register_converter("DATETIME", convert_datetime_iso)
sqlite3.register_converter("timestamp", convert_datetime_iso)

def allowed_file(filename):
    if not filename: return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Authentication Decorators & User Loading ---
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if getattr(g, 'user', None) is None:
            flash('Please log in to access this page.', 'error'); return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        current_user = getattr(g, 'user', None)
        if not current_user or not current_user['is_admin']:
            flash('You do not have permission to access this page.', 'error'); return redirect(url_for('dashboard'))
        return view(**kwargs)
    return wrapped_view

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id'); g.user = None
    if user_id is not None:
        db = get_db()
        g.user = db.execute('SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)).fetchone()

@app.context_processor
def inject_now(): return {'now': datetime.utcnow()}

# --- Main Routes (Index, Register, Login, Logout) ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    if getattr(g, 'user', None): flash("Already logged in. Logout to register a new account.", "info"); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']; password = request.form['password']; db = get_db(); error = None
        if not username: error = 'Username is required.'
        elif not password: error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone(): error = f"User '{username}' already registered."
        if error is None:
            try:
                db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, generate_password_hash(password))) # Default is_admin is 0 by schema
                db.commit(); flash('Registration successful! Please log in.', 'success'); return redirect(url_for('login'))
            except db.IntegrityError: error = f"User '{username}' already registered (DB)."
            except Exception as e: app.logger.error(f"Registration error: {e}"); error = "Unexpected registration error."
        if error: flash(error, 'error')
    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if getattr(g, 'user', None): flash("Already logged in.", "info"); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']; password = request.form['password']; db = get_db(); error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user is None: error = 'Incorrect username or user does not exist.'
        elif not check_password_hash(user['password_hash'], password): error = 'Incorrect password.'
        if error is None:
            session.clear(); session['user_id'] = user['id']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash(error, 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout(): session.clear(); flash('You have been logged out.', 'success'); return redirect(url_for('index'))

# --- Dashboard Route ---
@app.route('/dashboard')
@login_required
def dashboard():
    current_user = getattr(g, 'user', None)
    # This check is mostly redundant due to @login_required but good for clarity
    if not current_user: return redirect(url_for('login')) 

    db = get_db()
    if current_user['is_admin']:
        all_users = db.execute('SELECT id, username, is_admin, full_name, gender, department FROM users ORDER BY username').fetchall()
        unread_messages_count = db.execute('SELECT COUNT(id) FROM messages WHERE is_read = 0').fetchone()[0]
        pending_requests_count = db.execute("SELECT COUNT(id) FROM requests WHERE status = 'pending'").fetchone()[0]
        return render_template('dashboard_admin.html', all_users=all_users, unread_messages_count=unread_messages_count, pending_requests_count=pending_requests_count)
    else:
        user_requests_raw = db.execute("SELECT r.id, r.request_type, r.details, r.status, r.submitted_at, r.admin_notes, r.payslip_filename FROM requests r WHERE r.user_id = ? ORDER BY r.submitted_at DESC", (current_user['id'],)).fetchall()
        user_requests_processed = []
        for row in user_requests_raw:
            item = dict(row)
            ts_val = item.get('submitted_at')
            if isinstance(ts_val, datetime): item['submitted_at'] = ts_val
            elif isinstance(ts_val, (str, bytes)): item['submitted_at'] = convert_datetime_iso(ts_val if isinstance(ts_val, bytes) else ts_val.encode())
            else: item['submitted_at'] = None
            user_requests_processed.append(item)

        user_messages_raw = db.execute("SELECT m.id, m.sender_id, m.subject, m.body, m.timestamp, m.is_read, (SELECT COUNT(a.id) FROM attachments a WHERE a.message_id = m.id) as attachment_count FROM messages m WHERE m.sender_id = ? ORDER BY m.timestamp DESC", (current_user['id'],)).fetchall()
        user_messages_processed = []
        for row in user_messages_raw:
            item = dict(row)
            ts_val = item.get('timestamp')
            if isinstance(ts_val, datetime): item['timestamp'] = ts_val
            elif isinstance(ts_val, (str, bytes)): item['timestamp'] = convert_datetime_iso(ts_val if isinstance(ts_val, bytes) else ts_val.encode())
            else: item['timestamp'] = None
            user_messages_processed.append(item)
        return render_template('dashboard_user.html', user_requests=user_requests_processed, user_messages=user_messages_processed)

# --- Admin User Management ---
@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip(); password = request.form.get('password')
        is_admin = 'is_admin' in request.form; full_name = request.form.get('full_name', '').strip()
        gender = request.form.get('gender'); department = request.form.get('department')
        db = get_db(); error = None
        if not username: error = 'Username required.'
        elif not password: error = 'Password required.'
        elif not full_name: error = 'Full Name required.'
        elif gender and gender not in GENDER_CHOICES: error = 'Invalid gender.'
        elif department and department not in DEPARTMENT_CHOICES: error = 'Invalid department.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone(): error = f"User '{username}' exists."
        if error is None:
            try:
                db.execute('INSERT INTO users (username, password_hash, is_admin, full_name, gender, department) VALUES (?, ?, ?, ?, ?, ?)',(username, generate_password_hash(password), 1 if is_admin else 0, full_name, gender, department))
                db.commit(); flash(f'User {username} ({full_name}) created.', 'success'); return redirect(url_for('dashboard'))
            except Exception as e: db.rollback(); app.logger.error(f"User creation error: {e}"); error = "Unexpected error creating user."
        if error: flash(error, 'error')
    return render_template('admin_user_form.html', action="Create", user=None, department_choices=DEPARTMENT_CHOICES, gender_choices=GENDER_CHOICES, form_data=request.form if request.method == 'POST' else {})

@app.route('/admin/users/update/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    db = get_db()
    user_to_update = db.execute('SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_to_update: flash('User not found.', 'error'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        new_password = request.form.get('password'); is_admin = 'is_admin' in request.form
        full_name = request.form.get('full_name', '').strip(); gender = request.form.get('gender')
        department = request.form.get('department'); error = None
        if not full_name: error = 'Full Name required.'
        elif gender and gender not in GENDER_CHOICES: error = 'Invalid gender.'
        elif department and department not in DEPARTMENT_CHOICES: error = 'Invalid department.'
        if error is None:
            query_parts = ["is_admin = ?", "full_name = ?", "gender = ?", "department = ?"]
            params = [1 if is_admin else 0, full_name, gender, department]
            if new_password: query_parts.append("password_hash = ?"); params.append(generate_password_hash(new_password))
            params.append(user_id); query = f"UPDATE users SET {', '.join(query_parts)} WHERE id = ?"
            try:
                db.execute(query, tuple(params)); db.commit(); flash(f'User {user_to_update["username"]} updated.', 'success'); return redirect(url_for('dashboard'))
            except Exception as e: db.rollback(); app.logger.error(f"User update error: {e}"); error = "Unexpected error updating user."
        if error: flash(error, 'error')
    return render_template('admin_user_form.html', action="Update", user=user_to_update, department_choices=DEPARTMENT_CHOICES, gender_choices=GENDER_CHOICES)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    current_user = getattr(g, 'user', None)
    if current_user and current_user['id'] == user_id: flash("Cannot delete self.", "error"); return redirect(url_for('dashboard'))
    db = get_db()
    messages_by_user = db.execute('SELECT id FROM messages WHERE sender_id = ?', (user_id,)).fetchall()
    for msg in messages_by_user:
        attachments = db.execute('SELECT stored_filename FROM attachments WHERE message_id = ?', (msg['id'],)).fetchall()
        for att in attachments:
            if att['stored_filename']:
                try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename']))
                except OSError as e: app.logger.error(f"Error deleting file {att['stored_filename']}: {e}")
    db.execute('DELETE FROM messages WHERE sender_id = ?', (user_id,))
    requests_with_payslips = db.execute('SELECT payslip_filename FROM requests WHERE user_id = ? AND payslip_filename IS NOT NULL', (user_id,)).fetchall()
    for req_ps in requests_with_payslips:
        if req_ps['payslip_filename']:
            try: os.remove(os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], req_ps['payslip_filename']))
            except OSError as e: app.logger.error(f"Error deleting payslip {req_ps['payslip_filename']}: {e}")
    db.execute('DELETE FROM requests WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit(); flash('User and related data deleted.', 'success'); return redirect(url_for('dashboard'))

@app.route('/admin/users/view/<int:user_id>')
@login_required
@admin_required
def admin_view_user_profile(user_id):
    db = get_db()
    user = db.execute('SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user: flash('User not found.', 'error'); return redirect(url_for('dashboard'))
    messages_sent_raw = db.execute("SELECT m.id, m.subject, m.body, m.timestamp, m.is_read, (SELECT COUNT(a.id) FROM attachments a WHERE a.message_id = m.id) as attachment_count FROM messages m WHERE m.sender_id = ? ORDER BY m.timestamp DESC", (user_id,)).fetchall()
    messages_sent_processed = []
    for row in messages_sent_raw:
        item = dict(row); ts_val = item.get('timestamp')
        if isinstance(ts_val, datetime): item['timestamp'] = ts_val
        elif isinstance(ts_val, (str,bytes)): item['timestamp'] = convert_datetime_iso(ts_val if isinstance(ts_val, bytes) else ts_val.encode())
        else: item['timestamp'] = None
        messages_sent_processed.append(item)
    requests_made_raw = db.execute("SELECT id, request_type, details, status, submitted_at, admin_notes, payslip_filename FROM requests WHERE user_id = ? ORDER BY submitted_at DESC", (user_id,)).fetchall()
    requests_made_processed = []
    for row in requests_made_raw:
        item = dict(row); ts_val = item.get('submitted_at')
        if isinstance(ts_val, datetime): item['submitted_at'] = ts_val
        elif isinstance(ts_val, (str,bytes)): item['submitted_at'] = convert_datetime_iso(ts_val if isinstance(ts_val, bytes) else ts_val.encode())
        else: item['submitted_at'] = None
        requests_made_processed.append(item)
    return render_template('admin_user_profile.html', target_user=user, messages_sent=messages_sent_processed, requests_made=requests_made_processed)

# --- Messaging Routes ---
@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    current_user = getattr(g, 'user', None); prefill_subject = ''
    if request.method == 'POST':
        prefill_subject = request.form.get('subject', '')
        try: subject = request.form['subject']; body = request.form['body']
        except KeyError as ke: app.logger.error(f"Msg send KeyError: {ke}"); flash(f"Missing: {ke}.", "error"); return render_template('send_message.html', prefill_subject=prefill_subject)
        attachment = request.files.get('attachment'); error = None
        if not subject.strip(): error = "Subject required."
        elif not body.strip(): error = "Body required."
        stored_filename = None; original_filename_for_db = None
        if attachment and attachment.filename:
            original_filename_secure = secure_filename(attachment.filename)
            if not original_filename_secure: error = "Invalid attachment name." if not error else error
            elif allowed_file(original_filename_secure):
                original_filename_for_db = original_filename_secure
                file_ext = original_filename_secure.rsplit('.', 1)[1].lower() if '.' in original_filename_secure else ""
                stored_filename = f"{uuid.uuid4().hex}.{file_ext}" if file_ext else uuid.uuid4().hex
                try: attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                except Exception as e: app.logger.error(f"File save error: {e}"); error = "Save attachment failed."; stored_filename=None; original_filename_for_db=None;
            else: error = "Invalid file type." if not error else error
        if error is None:
            db = get_db(); cursor = db.cursor()
            try:
                cursor.execute('INSERT INTO messages (sender_id, subject, body) VALUES (?, ?, ?)', (current_user['id'], subject, body))
                message_id = cursor.lastrowid
                if stored_filename and original_filename_for_db:
                    cursor.execute('INSERT INTO attachments (message_id, original_filename, stored_filename) VALUES (?, ?, ?)', (message_id, original_filename_for_db, stored_filename))
                db.commit(); flash('Message sent!', 'success'); return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback(); app.logger.error(f"Msg DB error: {e}"); error = "Send message error."
                if stored_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)):
                    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                    except Exception as del_e: app.logger.error(f"Orphan file del error: {del_e}")
        if error: flash(error, 'error')
    return render_template('send_message.html', prefill_subject=prefill_subject)

@app.route('/admin/messages')
@login_required
@admin_required
def admin_view_messages():
    db = get_db()
    messages_raw = db.execute("SELECT m.id, m.subject, m.body, m.timestamp, m.is_read, u.username as sender_username FROM messages m JOIN users u ON m.sender_id = u.id ORDER BY m.timestamp DESC").fetchall()
    processed_messages = []
    for row in messages_raw:
        item = dict(row); ts_val = item.get('timestamp')
        if isinstance(ts_val, datetime): item['timestamp'] = ts_val
        elif isinstance(ts_val, (str,bytes)): item['timestamp'] = convert_datetime_iso(ts_val if isinstance(ts_val, bytes) else ts_val.encode())
        else: item['timestamp'] = None
        item['attachments'] = db.execute('SELECT id, original_filename, stored_filename FROM attachments WHERE message_id = ?', (item['id'],)).fetchall()
        processed_messages.append(item)
    return render_template('admin_view_messages.html', messages=processed_messages)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    current_user = getattr(g, 'user', None)
    if not current_user: flash("Auth required.", "error"); return redirect(url_for('login'))
    can_download = current_user['is_admin']
    if not can_download:
        db = get_db()
        att_info = db.execute("SELECT m.sender_id FROM attachments a JOIN messages m ON a.message_id = m.id WHERE a.stored_filename = ?", (filename,)).fetchone()
        if att_info and att_info['sender_id'] == current_user['id']: can_download = True
    if not can_download: flash("No permission.", "error"); return redirect(url_for('dashboard'))
    try: return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError: flash("File not found.", "error"); return redirect(url_for('admin_view_messages') if current_user['is_admin'] else url_for('dashboard'))

@app.route('/admin/messages/mark_read/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def admin_mark_message_read(message_id):
    db=get_db(); db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,)); db.commit()
    flash('Marked read.', 'success'); return redirect(url_for('admin_view_messages'))

@app.route('/admin/messages/delete/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_message(message_id):
    db=get_db(); msg_to_del = db.execute('SELECT id FROM messages WHERE id = ?', (message_id,)).fetchone()
    if not msg_to_del: flash('Msg not found.', 'error'); return redirect(url_for('admin_view_messages'))
    try:
        attachments = db.execute('SELECT stored_filename FROM attachments WHERE message_id = ?', (message_id,)).fetchall()
        for att in attachments: # Delete general attachments from UPLOAD_FOLDER
            if att['stored_filename']:
                gen_att_path = os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename'])
                if os.path.exists(gen_att_path):
                    try: os.remove(gen_att_path); app.logger.info(f"Deleted gen att: {gen_att_path}")
                    except OSError as e: app.logger.error(f"Error deleting gen att {gen_att_path}: {e}")
        db.execute('DELETE FROM messages WHERE id = ?', (message_id,)) # Cascades to attachments table rows
        db.commit(); flash('Message deleted.', 'success')
    except Exception as e: db.rollback(); app.logger.error(f"Admin msg del error: {e}"); flash('Error deleting msg.', 'error')
    return redirect(url_for('admin_view_messages'))

@app.route('/my_messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message_by_user(message_id):
    db=get_db(); current_user=getattr(g, 'user', None)
    msg = db.execute('SELECT id, sender_id FROM messages WHERE id = ?', (message_id,)).fetchone()
    if msg is None: flash('Msg not found.', 'error')
    elif msg['sender_id'] != current_user['id']: flash('No permission.', 'error')
    else:
        try:
            attachments = db.execute('SELECT stored_filename FROM attachments WHERE message_id = ?', (message_id,)).fetchall()
            for att in attachments:
                if att['stored_filename']:
                    gen_att_path = os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename'])
                    if os.path.exists(gen_att_path):
                        try: os.remove(gen_att_path)
                        except OSError as e: app.logger.error(f"User del att error: {e}")
            db.execute('DELETE FROM messages WHERE id = ?', (message_id,)); db.commit(); flash('Message deleted.', 'success')
        except Exception as e: db.rollback(); app.logger.error(f"User msg del error: {e}"); flash('Error deleting msg.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/my_requests/<int:request_id>/delete', methods=['POST'])
@login_required
def delete_request_by_user(request_id):
    db=get_db(); current_user=getattr(g, 'user', None)
    req = db.execute('SELECT id, user_id, status, payslip_filename, request_type FROM requests WHERE id = ?', (request_id,)).fetchone()
    if req is None: flash('Request not found.', 'error')
    elif req['user_id'] != current_user['id']: flash('No permission.', 'error')
    elif req['status'] != 'pending': flash('Only pending requests can be deleted.', 'info')
    else:
        try:
            if req['request_type'] == 'payslip' and req['payslip_filename']: # Delete associated payslip file if it's a pending payslip request
                 payslip_path = os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], req['payslip_filename'])
                 if os.path.exists(payslip_path):
                    try: os.remove(payslip_path); app.logger.info(f"User deleted pending payslip file: {payslip_path}")
                    except OSError as e: app.logger.error(f"Error deleting payslip on req del: {e}")
            db.execute('DELETE FROM requests WHERE id = ?', (request_id,)); db.commit(); flash('Request deleted.', 'success')
        except Exception as e: db.rollback(); app.logger.error(f"User req del error: {e}"); flash('Error deleting req.', 'error')
    return redirect(url_for('dashboard'))

# --- Payslip Generation and Request Update ---
def generate_payslip_pdf(user_profile_data, request_details_text, payslip_period_str):
    # FAKE DATA - REPLACE WITH REAL LOGIC
    earnings = {'basic_salary': 5000.00, 'allowances': 500.00}
    earnings['gross_earnings'] = sum(earnings.values())
    deductions = {'income_tax': 750.00, 'other_deductions': 150.00}
    deductions['total_deductions'] = sum(deductions.values())
    net_pay = earnings['gross_earnings'] - deductions['total_deductions']
    generation_date = datetime.utcnow().strftime('%d %b %Y, %H:%M:%S UTC')

    html_out = render_template('payslip_template.html', user=user_profile_data, payslip_period=payslip_period_str, earnings=earnings, deductions=deductions, net_pay=net_pay, generation_date=generation_date)
    
    period_slug = payslip_period_str.lower().replace(" ", "_").replace(",", "").replace(":", "")
    filename = f"payslip_user{user_profile_data['id']}_{period_slug}_{uuid.uuid4().hex[:8]}.pdf"
    filepath = os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], filename)
    try:
        HTML(string=html_out).write_pdf(filepath); app.logger.info(f"Generated PDF: {filepath}"); return filename
    except Exception as e: app.logger.error(f"PDF gen error for user {user_profile_data['id']}: {e}"); raise

@app.route('/admin/requests') # The URL path
@login_required
@admin_required
def admin_view_requests(): # The function name, which becomes the endpoint
    db = get_db()
    # Added r.payslip_filename to the SELECT statement
    requests_raw = db.execute("SELECT r.id, r.request_type, r.details, r.status, r.submitted_at, r.admin_notes, r.payslip_filename, u.username as user_username FROM requests r JOIN users u ON r.user_id = u.id ORDER BY r.status = 'pending' DESC, r.submitted_at DESC").fetchall()
    requests_processed = []
    for req_row in requests_raw:
        req_dict = dict(req_row)
        submitted_at_val = req_dict.get('submitted_at')
        if isinstance(submitted_at_val, datetime): req_dict['submitted_at'] = submitted_at_val
        elif isinstance(submitted_at_val, (str,bytes)): # Handle bytes for convert_datetime_iso
            req_dict['submitted_at'] = convert_datetime_iso(submitted_at_val if isinstance(submitted_at_val, bytes) else submitted_at_val.encode())
        else: req_dict['submitted_at'] = None
        requests_processed.append(req_dict)
    return render_template('admin_view_requests.html', requests=requests_processed)



@app.route('/admin/requests/update_status/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_request_status(request_id):
    db=get_db()
    req_info = db.execute('SELECT r.id, r.request_type, r.details, r.user_id, r.payslip_filename, u.username, u.full_name, u.department FROM requests r JOIN users u ON r.user_id = u.id WHERE r.id = ?', (request_id,)).fetchone()
    if not req_info: flash("Request not found.", "error"); return redirect(url_for('admin_view_requests'))

    new_status = request.form.get('status'); admin_notes = request.form.get('admin_notes', '').strip(); error = None
    generated_filename = None # This will hold the name of the newly generated payslip

    if new_status not in ['pending', 'approved', 'rejected']: error = "Invalid status."
    
    if not error and new_status == 'approved' and req_info['request_type'] == 'payslip':
        try:
            if req_info['payslip_filename']: # An old payslip exists, delete it
                old_path = os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], req_info['payslip_filename'])
                if os.path.exists(old_path):
                    try: os.remove(old_path); app.logger.info(f"Deleted old payslip: {old_path}")
                    except OSError as e: app.logger.error(f"Error deleting old payslip {old_path}: {e}") # Log but continue
            
            period_detail = req_info['details']
            period = period_detail.split("Payslip for:",1)[-1].strip() if "Payslip for:" in period_detail else "UnknownPeriod"
            user_data = {'id': req_info['user_id'], 'username': req_info['username'], 'full_name': req_info['full_name'], 'department': req_info['department']}
            generated_filename = generate_payslip_pdf(user_data, req_info['details'], period) # Store the new filename
        except Exception as e_gen: app.logger.error(f"Payslip gen failed for req {request_id}: {e_gen}"); error = "Payslip PDF generation failed."

    if error:
        flash(error, 'error')
        # If generation failed for an approval, we might not want to proceed with DB update for payslip_filename
        # The logic below handles not setting filename if generation failed
    
    # Proceed with DB update regardless of payslip generation outcome for status/notes,
    # but only update payslip_filename if generation was successful.
    try:
        if new_status == 'approved' and req_info['request_type'] == 'payslip':
            if generated_filename: # New payslip was successfully generated
                db.execute('UPDATE requests SET status=?, admin_notes=?, payslip_filename=? WHERE id=?', (new_status, admin_notes, generated_filename, request_id))
                flash('Request approved and payslip generated.', 'success')
            else: # Generation failed or was not applicable (e.g. already had filename and no error)
                # If error was set, it's already flashed. If no error but no new file, means we keep old or it wasn't a new approval.
                # Only update status and notes if no new file was to be generated/or failed.
                db.execute('UPDATE requests SET status=?, admin_notes=? WHERE id=?', (new_status, admin_notes, request_id))
                if not error: # Avoid double flashing if generation error occurred
                     flash('Request status updated (payslip unchanged or generation failed).', 'info' if error else 'success')
        else: # For other request types or non-approval status changes
            db.execute('UPDATE requests SET status=?, admin_notes=? WHERE id=?', (new_status, admin_notes, request_id))
            if not error: flash('Request status updated.', 'success')
        db.commit()
    except Exception as e_db:
        db.rollback(); app.logger.error(f"Req status DB update error: {e_db}"); flash("DB error updating request.", "error")
        # Clean up newly generated file if DB update failed
        if generated_filename and os.path.exists(os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], generated_filename)):
            try: os.remove(os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], generated_filename))
            except OSError as e_del: app.logger.error(f"Error deleting orphaned payslip on DB fail: {e_del}")
            
    return redirect(url_for('admin_view_requests'))


@app.route('/admin/requests/delete/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_request(request_id):
    db = get_db()
    request_to_delete = db.execute(
        'SELECT id, request_type, payslip_filename FROM requests WHERE id = ?', (request_id,)
    ).fetchone()

    if not request_to_delete:
        flash('Request not found.', 'error')
        return redirect(url_for('admin_view_requests'))

    try:
        # If the request was a payslip and had an associated file, delete it
        if request_to_delete['request_type'] == 'payslip' and request_to_delete['payslip_filename']:
            payslip_path = os.path.join(app.config['PAYSLIP_UPLOAD_FOLDER'], request_to_delete['payslip_filename'])
            if os.path.exists(payslip_path):
                try:
                    os.remove(payslip_path)
                    app.logger.info(f"Admin deleted payslip file: {payslip_path}")
                except OSError as e:
                    app.logger.error(f"Error deleting payslip file {payslip_path} by admin: {e}")
        
        db.execute('DELETE FROM requests WHERE id = ?', (request_id,))
        db.commit()
        flash('Request (ID: {}) deleted successfully.'.format(request_id), 'success')
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting request {request_id} by admin: {e}")
        flash('An error occurred while deleting the request.', 'error')

    return redirect(url_for('admin_view_requests'))


@app.route('/payslips/<path:filename>')
@login_required
def view_payslip(filename):
    db=get_db(); current_user=getattr(g, 'user', None)
    if not current_user: flash("Auth required", "error"); return redirect(url_for('login'))

    req_owner = db.execute("SELECT user_id FROM requests WHERE payslip_filename = ?", (filename,)).fetchone()
    if not req_owner: flash("Payslip record not found.", "error"); return redirect(url_for('dashboard'))
    
    if not current_user['is_admin'] and req_owner['user_id'] != current_user['id']:
        flash("No permission to view this payslip.", "error"); return redirect(url_for('dashboard'))
    
    try: return send_from_directory(app.config['PAYSLIP_UPLOAD_FOLDER'], filename, as_attachment=False)
    except FileNotFoundError: flash("Payslip file not found on server.", "error"); return redirect(url_for('admin_view_requests') if current_user['is_admin'] else url_for('dashboard'))

@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request_form():
    current_user = getattr(g, 'user', None)
    request_type_arg = request.args.get('type', 'payslip'); error = None
    form_data = request.form if request.method == 'POST' else {}
    if request.method == 'POST':
        actual_request_type = form_data.get('request_type', request_type_arg); details = ""
        if actual_request_type == 'payslip':
            month = form_data.get('payslip_month'); year = form_data.get('payslip_year')
            if month and year: details = f"Payslip for: {month} {year}"
            else: error = "Month and year required for payslip."
        elif actual_request_type == 'vacation':
            start_date_str = form_data.get('start_date'); end_date_str = form_data.get('end_date'); reason = form_data.get('vacation_reason', '').strip()
            if not start_date_str or not end_date_str: error = "Start and end dates required for vacation." if not error else error
            else:
                try:
                    start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d'); end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d')
                    if end_date_obj < start_date_obj: error = "End date before start date." if not error else error
                    else:
                        duration = (end_date_obj - start_date_obj).days + 1
                        details = f"Vacation: {start_date_obj.strftime('%b %d, %Y')} to {end_date_obj.strftime('%b %d, %Y')} ({duration} day{'s' if duration != 1 else ''})."
                        if reason: details += f" Reason: {reason}"
                except ValueError: error = "Invalid date format." if not error else error
        else: # For other generic request types
            details_from_form = form_data.get('details', '').strip()
            if not details_from_form : error = "Details for this request type are required." if not error else error
            else: details = details_from_form

        if not details and not error: error = "Details required or could not be determined." # Final check
        
        if error is None:
            db = get_db()
            try:
                db.execute('INSERT INTO requests (user_id, request_type, details) VALUES (?, ?, ?)', (current_user['id'], actual_request_type, details)); db.commit()
                flash(f'{actual_request_type.capitalize()} request submitted!', 'success'); return redirect(url_for('dashboard'))
            except Exception as e: db.rollback(); app.logger.error(f"New request DB error: {e}"); error = "Unexpected error submitting request."
        if error: flash(error, 'error')

    form_title, icon_class = "", "fa-clipboard-list"; current_year = datetime.utcnow().year
    years_for_select = list(range(current_year, current_year - 6, -1))
    months_for_select = ["January","February","March","April","May","June","July","August","September","October","November","December"]
    final_request_type_for_template = form_data.get('request_type', request_type_arg)

    if final_request_type_for_template == 'payslip': form_title, icon_class = "Request Payslip", "fa-file-invoice-dollar"
    elif final_request_type_for_template == 'vacation': form_title, icon_class = "Request Vacation Time", "fa-plane-departure"
    elif final_request_type_for_template and final_request_type_for_template not in ['payslip', 'vacation']:
        # Handle a potential generic request type if you plan to add more
        form_title, icon_class = f"New {final_request_type_for_template.capitalize()} Request", "fa-edit"
    elif not final_request_type_for_template : # Should not happen if arg has default
         flash("Invalid request type.", "error"); return redirect(url_for('dashboard'))


    return render_template('new_request_form.html', request_type=final_request_type_for_template, form_title=form_title, icon_class=icon_class, years_for_select=years_for_select, months_for_select=months_for_select, form_data=form_data, error=error)


@app.template_filter()
@pass_eval_context
def nl2br(eval_ctx, value):
    if not value: return ""
    br = Markup("<br>\n"); str_value = str(value) if not isinstance(value, str) else value
    processed_value = str_value
    if eval_ctx.autoescape: processed_value = escape(str_value)
    result = processed_value.replace('\n', br)
    return Markup(result)

if __name__ == '__main__':
    db_path = app.config['DATABASE']
    if not os.path.exists(app.instance_path):
        try: os.makedirs(app.instance_path, exist_ok=True)
        except OSError as e: print(f"Error creating instance folder: {e}")
    if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        with app.app_context():
            print("Database not found or empty. Initializing...")
            try: init_db(); print(f"Database initialized at {db_path}")
            except Exception as e: print(f"Error during database initialization: {e}")
    app.run(debug=True)