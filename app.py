import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename # For secure file handling
from functools import wraps
import click
from datetime import datetime
from jinja2 import pass_eval_context
from markupsafe import Markup, escape
import uuid # For unique filenames

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DATABASE'] = os.path.join(app.instance_path, 'users.db')

# Configuration for file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads') # CORRECTED LINE

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx'}

# Define department options globally or pass from route
DEPARTMENT_CHOICES = ["Human Resources", "IT", "Marketing", "Sales", "Operations", "Finance", "Workers"]
GENDER_CHOICES = ["Male", "Female", "Other", "Prefer not to say"]


# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        try:
            os.makedirs(app.instance_path, exist_ok=True) # exist_ok=True handles existing directory
        except OSError as e:
            app.logger.error(f"Error creating instance path: {e}")
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    # Ensure instance path exists before trying to open schema.sql from app's resource location
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass # Should not happen with exist_ok=True
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

app.teardown_appcontext(close_db)

# --- CLI command to make a user admin ---
@app.cli.command('make-admin')
@click.argument('username')
def make_admin_command(username):
    """Makes an existing user an admin."""
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if user is None:
        click.echo(f"User {username} not found.")
        return
    db.execute('UPDATE users SET is_admin = 1 WHERE username = ?', (username,))
    db.commit()
    click.echo(f"User {username} is now an admin.")


def adapt_datetime_iso(val):
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return val.isoformat()

def convert_datetime_iso(val):
    """Convert ISO 8601_datetime_string to datetime.datetime object."""
    if not val: return None # Handle None or empty bytes
    val_str = val.decode()
    try:
        return datetime.fromisoformat(val_str)
    except (ValueError, AttributeError):
        try:
            return datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, AttributeError):
            try:
                return datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S")
            except (ValueError, AttributeError):
                app.logger.warning(f"Could not parse datetime string: {val_str}")
                return None

# Ensure upload folder exists
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) # Added exist_ok=True
except OSError:
    pass

def allowed_file(filename):
    if not filename: # Handle empty filename
        return False
    has_dot = '.' in filename
    if not has_dot:
        return False
    ext_parts = filename.rsplit('.', 1)
    if len(ext_parts) < 2:
        return False
    ext = ext_parts[1].lower()
    is_allowed = ext in ALLOWED_EXTENSIONS
    return is_allowed


sqlite3.register_adapter(datetime, adapt_datetime_iso)
sqlite3.register_converter("DATETIME", convert_datetime_iso)
sqlite3.register_converter("timestamp", convert_datetime_iso)


# --- Authentication Decorators ---
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if getattr(g, 'user', None) is None: # Safer check
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        current_user = getattr(g, 'user', None) # Safer check
        if not current_user or not current_user['is_admin']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return view(**kwargs)
    return wrapped_view

# --- Load Logged-in User ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None # Always initialize g.user to None
    if user_id is not None:
        db = get_db()
        g.user = db.execute(
            'SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)
        ).fetchone()


# --- Context Processor for Footer Year ---
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# --- Main Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    if getattr(g, 'user', None): # Safer check
        flash("You are already logged in. Logout to register a new account.", "info")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f"User '{username}' is already registered."

        if error is None:
            try:
                db.execute(
                    'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)',
                    (username, generate_password_hash(password))
                )
                db.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except db.IntegrityError: # More specific error
                error = f"User '{username}' is already registered (database integrity error)."
            except Exception as e:
                app.logger.error(f"Registration error: {e}")
                error = "An unexpected error occurred during registration."
        
        if error:
            flash(error, 'error')
        # Re-render register page on error
        return render_template('register.html') 

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if getattr(g, 'user', None): # Safer check
        flash("You are already logged in.", "info")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username or user does not exist.'
        elif not check_password_hash(user['password_hash'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            flash(f'Welcome back, {user["username"]}!', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('dashboard'))
        
        flash(error, 'error')
        # On login failure, re-render login page to show error
        return render_template('login.html') 

    return render_template('login.html') # For GET request

@app.route('/dashboard')
@login_required
def dashboard():
    current_user = getattr(g, 'user', None) # Ensure g.user is accessed safely
    if not current_user: # Should be caught by @login_required, but defensive
        return redirect(url_for('login'))

    if current_user['is_admin']:
        db = get_db()
        all_users = db.execute(
            'SELECT id, username, is_admin, full_name, gender, department FROM users ORDER BY username'
        ).fetchall()
        unread_messages_count = db.execute(
            'SELECT COUNT(id) FROM messages WHERE is_read = 0' # Assuming admin is recipient for all
        ).fetchone()[0]
        pending_requests_count = db.execute(
            "SELECT COUNT(id) FROM requests WHERE status = 'pending'"
        ).fetchone()[0]
        return render_template('dashboard_admin.html',
                               all_users=all_users,
                               unread_messages_count=unread_messages_count,
                               pending_requests_count=pending_requests_count)
    else:
        # --- Regular User Dashboard Logic ---
        db = get_db()

        # 1. Fetch User's Submitted Requests
        user_requests_raw = db.execute(
            """SELECT id, request_type, details, status, submitted_at, admin_notes
               FROM requests
               WHERE user_id = ?
               ORDER BY submitted_at DESC""",
            (current_user['id'],)
        ).fetchall()
        user_requests_processed = []
        if user_requests_raw:
            for req_row in user_requests_raw:
                req_dict = dict(req_row)
                # Robust timestamp conversion
                submitted_at_val = req_dict.get('submitted_at')
                if isinstance(submitted_at_val, datetime):
                    req_dict['submitted_at'] = submitted_at_val
                elif isinstance(submitted_at_val, str):
                    try:
                        req_dict['submitted_at'] = datetime.fromisoformat(submitted_at_val.replace('Z', '+00:00'))
                    except ValueError:
                        try:
                            req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S.%f')
                        except ValueError:
                            try:
                                req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S')
                            except ValueError as e_parse:
                                app.logger.error(f"Error parsing user_request submitted_at string '{submitted_at_val}': {e_parse}")
                                req_dict['submitted_at'] = None
                else:
                    req_dict['submitted_at'] = None
                user_requests_processed.append(req_dict)

        # 2. Fetch User's Sent Messages
        user_messages_raw = db.execute(
            """SELECT m.id, m.sender_id, m.subject, m.body, m.timestamp, m.is_read,
                      (SELECT COUNT(a.id) FROM attachments a WHERE a.message_id = m.id) as attachment_count
               FROM messages m
               WHERE m.sender_id = ?
               ORDER BY m.timestamp DESC""",
            (g.user['id'],) # Use g.user here as current_user is already established
        ).fetchall()

        user_messages_processed = []
        if user_messages_raw:
            for msg_row in user_messages_raw:
                msg_dict = dict(msg_row)
                timestamp_val = msg_dict.get('timestamp')
                if isinstance(timestamp_val, datetime):
                    msg_dict['timestamp'] = timestamp_val
                elif isinstance(timestamp_val, str):
                    try:
                        msg_dict['timestamp'] = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
                    except ValueError:
                        try:
                            msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S.%f')
                        except ValueError:
                            try:
                                msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S')
                            except ValueError as e_parse:
                                app.logger.error(f"Error parsing user_message timestamp string '{timestamp_val}': {e_parse}")
                                msg_dict['timestamp'] = None
                else:
                    msg_dict['timestamp'] = None
                user_messages_processed.append(msg_dict)

        return render_template('dashboard_user.html',
                               user_requests=user_requests_processed,
                               user_messages=user_messages_processed)

@app.route('/logout')
@login_required # Ensure user is logged in to log out
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# --- Admin User Management Routes ---
@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        full_name = request.form.get('full_name', '').strip()
        gender = request.form.get('gender')
        department = request.form.get('department')
        
        db = get_db()
        error = None

        if not username: error = 'Username is required.'
        elif not password: error = 'Password is required.'
        elif not full_name: error = 'Full Name is required.'
        elif gender and gender not in GENDER_CHOICES: error = 'Invalid gender selected.'
        elif department and department not in DEPARTMENT_CHOICES: error = 'Invalid department selected.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            error = f"User '{username}' already exists."

        if error is None:
            try:
                db.execute(
                    '''INSERT INTO users (username, password_hash, is_admin, full_name, gender, department)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (username, generate_password_hash(password), 1 if is_admin else 0,
                     full_name, gender, department)
                )
                db.commit()
                flash(f'User {username} ({full_name}) created successfully.', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error creating user: {e}")
                error = "An unexpected error occurred while creating the user."
        
        if error: flash(error, 'error')
    
    return render_template('admin_user_form.html',
                           action="Create",
                           user=None,
                           department_choices=DEPARTMENT_CHOICES,
                           gender_choices=GENDER_CHOICES,
                           form_data=request.form if request.method == 'POST' else {})

@app.route('/admin/users/update/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    db = get_db()
    user_to_update = db.execute(
        'SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    if not user_to_update:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        full_name = request.form.get('full_name', '').strip()
        gender = request.form.get('gender')
        department = request.form.get('department')
        error = None

        if not full_name: error = 'Full Name is required.'
        elif gender and gender not in GENDER_CHOICES: error = 'Invalid gender selected.'
        elif department and department not in DEPARTMENT_CHOICES: error = 'Invalid department selected.'

        if error is None:
            query_parts = ["is_admin = ?", "full_name = ?", "gender = ?", "department = ?"]
            params = [1 if is_admin else 0, full_name, gender, department]

            if new_password:
                query_parts.append("password_hash = ?")
                params.append(generate_password_hash(new_password))
            
            params.append(user_id)
            query = f"UPDATE users SET {', '.join(query_parts)} WHERE id = ?"
            
            try:
                db.execute(query, tuple(params))
                db.commit()
                flash(f'User {user_to_update["username"]} updated successfully.', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error updating user: {e}")
                error = "An unexpected error occurred while updating the user."

        if error: flash(error, 'error')
    
    return render_template('admin_user_form.html',
                           action="Update",
                           user=user_to_update,
                           department_choices=DEPARTMENT_CHOICES,
                           gender_choices=GENDER_CHOICES)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    current_user = getattr(g, 'user', None)
    if current_user and current_user['id'] == user_id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('dashboard'))
    
    db = get_db()
    # ON DELETE CASCADE in schema.sql should handle attachments if messages are deleted.
    # First, get message_ids for messages sent by this user to delete their attachments
    messages_by_user = db.execute('SELECT id FROM messages WHERE sender_id = ?', (user_id,)).fetchall()
    for msg in messages_by_user:
        attachments = db.execute('SELECT stored_filename FROM attachments WHERE message_id = ?', (msg['id'],)).fetchall()
        for att in attachments:
            if att['stored_filename'] and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename'])):
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], att['stored_filename']))
                except OSError as e:
                    app.logger.error(f"Error deleting attachment file {att['stored_filename']} for user {user_id}: {e}")
        # Attachments table has ON DELETE CASCADE for message_id, so they'll be removed when message is.

    db.execute('DELETE FROM messages WHERE sender_id = ?', (user_id,))
    db.execute('DELETE FROM requests WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User and their related data deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

# --- Messaging Routes ---
@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    current_user = getattr(g, 'user', None)
    if not current_user: return redirect(url_for('login')) # Should be caught by @login_required

    prefill_subject = ''
    if request.method == 'POST':
        prefill_subject = request.form.get('subject', '') # Keep prefill for errors
        try:
            subject = request.form['subject']
            body = request.form['body']
        except KeyError as ke:
            app.logger.error(f"KeyError accessing form data in send_message: {ke}")
            flash(f"Missing form field: {ke}. Please ensure all fields are filled.", "error")
            return render_template('send_message.html', prefill_subject=prefill_subject)

        attachment = request.files.get('attachment')
        error = None

        if not subject.strip(): error = "Subject is required." 
        elif not body.strip(): error = "Message body is required."

        stored_filename = None
        original_filename_for_db = None

        if attachment and attachment.filename:
            original_filename_from_secure = secure_filename(attachment.filename)
            if not original_filename_from_secure:
                if not error: error = "Invalid attachment filename (was sanitized to empty)."
            elif allowed_file(original_filename_from_secure):
                original_filename_for_db = original_filename_from_secure
                file_ext = original_filename_from_secure.rsplit('.', 1)[1].lower() if '.' in original_filename_from_secure else ""
                unique_id = uuid.uuid4().hex
                stored_filename = f"{unique_id}.{file_ext}" if file_ext else unique_id
                try:
                    attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                except Exception as e:
                    app.logger.error(f"File save error: {e}")
                    if not error: error = "Could not save attachment. Please try again."
                    stored_filename = None
                    original_filename_for_db = None
            else:
                if not error: error = "Invalid file type or filename. Allowed types: " + ", ".join(sorted(list(ALLOWED_EXTENSIONS)))
        
        if error is None:
            db = get_db()
            cursor = db.cursor()
            try:
                cursor.execute('INSERT INTO messages (sender_id, subject, body) VALUES (?, ?, ?)',
                               (current_user['id'], subject, body))
                message_id = cursor.lastrowid
                if stored_filename and original_filename_for_db and message_id:
                    cursor.execute('INSERT INTO attachments (message_id, original_filename, stored_filename) VALUES (?, ?, ?)',
                                   (message_id, original_filename_for_db, stored_filename))
                db.commit()
                flash('Message sent successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Message/Attachment DB error: {e}")
                error = "An error occurred while sending the message."
                if stored_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)):
                    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                    except Exception as del_e: app.logger.error(f"Error deleting orphaned file: {del_e}")
        
        if error: flash(error, 'error')

    return render_template('send_message.html', prefill_subject=prefill_subject)


@app.route('/admin/messages')
@login_required
@admin_required
def admin_view_messages():
    db = get_db()
    messages_raw = db.execute('''
        SELECT m.id, m.subject, m.body, m.timestamp, m.is_read, u.username as sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        ORDER BY m.timestamp DESC
    ''').fetchall()

    processed_messages = []
    for msg_row in messages_raw:
        msg_dict = dict(msg_row)
        timestamp_val = msg_dict.get('timestamp')
        if isinstance(timestamp_val, datetime):
            msg_dict['timestamp'] = timestamp_val
        elif isinstance(timestamp_val, str):
            try: msg_dict['timestamp'] = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
            except ValueError:
                try: msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try: msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S')
                    except ValueError as e_parse:
                        app.logger.error(f"Error parsing admin_view_messages timestamp '{timestamp_val}': {e_parse}")
                        msg_dict['timestamp'] = None
        else:
            msg_dict['timestamp'] = None
        
        attachments = db.execute('''
            SELECT id, original_filename, stored_filename
            FROM attachments
            WHERE message_id = ?
        ''', (msg_dict['id'],)).fetchall()
        msg_dict['attachments'] = attachments
        processed_messages.append(msg_dict)

    return render_template('admin_view_messages.html', messages=processed_messages)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Security: Check if the current user has permission to access this file.
    # This is a simplified check; more robust logic might be needed depending on requirements.
    current_user = getattr(g, 'user', None)
    if not current_user:
        flash("Authentication required.", "error")
        return redirect(url_for('login'))

    # Example: Allow admin to download any file.
    # If users should download their own attachments, you'll need more complex logic
    # to verify if the filename belongs to a message sent by or to them.
    if not current_user['is_admin']:
        # Check if this file belongs to a message sent by the current user
        attachment_message = db.execute(
            """SELECT m.sender_id FROM attachments a
               JOIN messages m ON a.message_id = m.id
               WHERE a.stored_filename = ?""", (filename,)
        ).fetchone()
        if not attachment_message or attachment_message['sender_id'] != current_user['id']:
            flash("You do not have permission to access this file.", "error")
            return redirect(url_for('dashboard'))
    
    try:
        # Use as_attachment=True to force download, False to display in browser if possible
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        flash("File not found.", "error")
        if current_user and current_user['is_admin']:
            return redirect(url_for('admin_view_messages'))
        return redirect(url_for('dashboard'))


@app.route('/admin/messages/mark_read/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def admin_mark_message_read(message_id):
    db = get_db()
    db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,))
    db.commit()
    flash('Message marked as read.', 'success')
    return redirect(url_for('admin_view_messages'))

# --- USER Deletion routes (Stage 1) ---
@app.route('/my_messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message_by_user(message_id):
    db = get_db()
    current_user = getattr(g, 'user', None)
    if not current_user: return redirect(url_for('login'))

    message = db.execute(
        'SELECT id, sender_id, is_read FROM messages WHERE id = ?', (message_id,)
    ).fetchone()

    if message is None:
        flash('Message not found.', 'error')
    elif message['sender_id'] != current_user['id']:
        flash('You do not have permission to delete this message.', 'error')
    # Optional: Add condition: and not message['is_read']
    # elif message['is_read']:
    #     flash('Cannot delete a message that has been read by an admin.', 'info')
    else:
        try:
            # ON DELETE CASCADE in schema should handle attachments
            db.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            db.commit()
            flash('Message and its attachments deleted successfully.', 'success')
        except Exception as e:
            db.rollback()
            app.logger.error(f"Error deleting message by user: {e}")
            flash('An error occurred while deleting the message.', 'error')
            
    return redirect(url_for('dashboard'))

@app.route('/my_requests/<int:request_id>/delete', methods=['POST'])
@login_required
def delete_request_by_user(request_id):
    db = get_db()
    current_user = getattr(g, 'user', None)
    if not current_user: return redirect(url_for('login'))

    user_request = db.execute(
        'SELECT id, user_id, status FROM requests WHERE id = ?', (request_id,)
    ).fetchone()

    if user_request is None: flash('Request not found.', 'error')
    elif user_request['user_id'] != current_user['id']: flash('You do not have permission to delete this request.', 'error')
    elif user_request['status'] != 'pending': flash('Only pending requests can be deleted.', 'info')
    else:
        try:
            db.execute('DELETE FROM requests WHERE id = ?', (request_id,))
            db.commit()
            flash('Request deleted successfully.', 'success')
        except Exception as e:
            db.rollback()
            app.logger.error(f"Error deleting request by user: {e}")
            flash('An error occurred while deleting the request.', 'error')
    return redirect(url_for('dashboard'))


# --- User Request Routes (Payslip, Vacation) ---
@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request_form():
    current_user = getattr(g, 'user', None)
    if not current_user: return redirect(url_for('login'))

    request_type_arg = request.args.get('type', 'payslip')
    error = None
    form_data = request.form if request.method == 'POST' else {}

    if request.method == 'POST':
        actual_request_type = form_data.get('request_type', request_type_arg)
        details = ""

        if actual_request_type == 'payslip':
            month = form_data.get('payslip_month')
            year = form_data.get('payslip_year')
            if month and year: details = f"Payslip for: {month} {year}"
            else: error = "Please select both month and year for the payslip request."
        
        elif actual_request_type == 'vacation':
            start_date_str = form_data.get('start_date')
            end_date_str = form_data.get('end_date')
            reason = form_data.get('vacation_reason', '').strip()

            if not start_date_str or not end_date_str:
                if not error: error = "Please select both a start and end date for your vacation."
            else:
                try:
                    start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d')
                    if end_date_obj < start_date_obj:
                        if not error: error = "End date cannot be before the start date."
                    else:
                        duration = (end_date_obj - start_date_obj).days + 1
                        details = f"Vacation: {start_date_obj.strftime('%b %d, %Y')} to {end_date_obj.strftime('%b %d, %Y')} ({duration} day{'s' if duration != 1 else ''})."
                        if reason: details += f" Reason: {reason}"
                except ValueError:
                    if not error: error = "Invalid date format submitted. Please use the calendar."
        else:
             details_from_form = form_data.get('details', '').strip()
             if not details_from_form and not error : error = "Details for the request are required."
             else: details = details_from_form
        
        if not details and not error : # Fallback if specific type logic didn't set details
            error = "Request details could not be determined. Please fill the form correctly."

        if error is None:
            db = get_db()
            try:
                db.execute('INSERT INTO requests (user_id, request_type, details) VALUES (?, ?, ?)',
                           (current_user['id'], actual_request_type, details))
                db.commit()
                flash(f'{actual_request_type.capitalize()} request submitted successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error inserting request into DB: {e}")
                error = "An unexpected error occurred while submitting your request."
        
        if error: flash(error, 'error')

    form_title, icon_class = "", "fa-clipboard-list"
    current_year = datetime.utcnow().year
    years_for_select = list(range(current_year, current_year - 6, -1))
    months_for_select = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

    final_request_type_for_template = form_data.get('request_type', request_type_arg)

    if final_request_type_for_template == 'payslip':
        form_title, icon_class = "Request Payslip", "fa-file-invoice-dollar"
    elif final_request_type_for_template == 'vacation':
        form_title, icon_class = "Request Vacation Time", "fa-plane-departure"
    elif final_request_type_for_template : # If type is somehow invalid from POST/GET
        flash("Invalid request type specified.", "error")
        return redirect(url_for('dashboard')) # Or show a generic form

    return render_template('new_request_form.html',
                           request_type=final_request_type_for_template,
                           form_title=form_title,
                           icon_class=icon_class,
                           years_for_select=years_for_select,
                           months_for_select=months_for_select,
                           form_data=form_data, # Pass form data for repopulation
                           error=error) # error is already flashed, but can be useful in template


@app.route('/admin/requests')
@login_required
@admin_required
def admin_view_requests():
    db = get_db()
    requests_raw = db.execute('''
        SELECT r.id, r.request_type, r.details, r.status, r.submitted_at, r.admin_notes, u.username as user_username
        FROM requests r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.status = 'pending' DESC, r.submitted_at DESC
    ''').fetchall()

    requests_processed = []
    for req_row in requests_raw:
        req_dict = dict(req_row)
        submitted_at_val = req_dict.get('submitted_at')
        if isinstance(submitted_at_val, datetime): req_dict['submitted_at'] = submitted_at_val
        elif isinstance(submitted_at_val, str):
            try: req_dict['submitted_at'] = datetime.fromisoformat(submitted_at_val.replace('Z', '+00:00'))
            except ValueError:
                try: req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try: req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S')
                    except ValueError as e_parse:
                        app.logger.error(f"Error parsing admin_view_requests submitted_at '{submitted_at_val}': {e_parse}")
                        req_dict['submitted_at'] = None
        else: req_dict['submitted_at'] = None
        requests_processed.append(req_dict)

    return render_template('admin_view_requests.html', requests=requests_processed)

@app.route('/admin/requests/update_status/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_request_status(request_id):
    new_status = request.form.get('status')
    admin_notes = request.form.get('admin_notes', '').strip()
    db = get_db()

    if new_status not in ['pending', 'approved', 'rejected']:
        flash("Invalid status.", "error")
    else:
        db.execute('UPDATE requests SET status = ?, admin_notes = ? WHERE id = ?',
                   (new_status, admin_notes, request_id))
        db.commit()
        flash('Request status updated.', 'success')
    return redirect(url_for('admin_view_requests'))
@app.route('/admin/users/view/<int:user_id>')
@login_required
@admin_required
def admin_view_user_profile(user_id):
    db = get_db()
    
    # 1. Fetch User Details
    user = db.execute(
        'SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard')) # Redirect to admin dashboard

    # 2. Fetch Messages Sent BY this User
    messages_sent_raw = db.execute('''
        SELECT m.id, m.subject, m.body, m.timestamp, m.is_read,
               (SELECT COUNT(a.id) FROM attachments a WHERE a.message_id = m.id) as attachment_count
        FROM messages m
        WHERE m.sender_id = ?
        ORDER BY m.timestamp DESC
    ''', (user_id,)).fetchall()

    messages_sent_processed = []
    for msg_row in messages_sent_raw:
        msg_dict = dict(msg_row)
        timestamp_val = msg_dict.get('timestamp')
        if isinstance(timestamp_val, datetime):
            msg_dict['timestamp'] = timestamp_val
        elif isinstance(timestamp_val, str):
            try: msg_dict['timestamp'] = datetime.fromisoformat(timestamp_val.replace('Z', '+00:00'))
            except ValueError:
                try: msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try: msg_dict['timestamp'] = datetime.strptime(timestamp_val, '%Y-%m-%d %H:%M:%S')
                    except ValueError as e_parse:
                        app.logger.error(f"Error parsing message timestamp for user profile '{timestamp_val}': {e_parse}")
                        msg_dict['timestamp'] = None
        else: msg_dict['timestamp'] = None
        messages_sent_processed.append(msg_dict)

    # 3. Fetch Requests Made BY this User
    requests_made_raw = db.execute('''
        SELECT id, request_type, details, status, submitted_at, admin_notes
        FROM requests
        WHERE user_id = ?
        ORDER BY submitted_at DESC
    ''', (user_id,)).fetchall()
    
    requests_made_processed = []
    for req_row in requests_made_raw:
        req_dict = dict(req_row)
        submitted_at_val = req_dict.get('submitted_at')
        if isinstance(submitted_at_val, datetime): req_dict['submitted_at'] = submitted_at_val
        elif isinstance(submitted_at_val, str):
            try: req_dict['submitted_at'] = datetime.fromisoformat(submitted_at_val.replace('Z', '+00:00'))
            except ValueError:
                try: req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try: req_dict['submitted_at'] = datetime.strptime(submitted_at_val, '%Y-%m-%d %H:%M:%S')
                    except ValueError as e_parse:
                        app.logger.error(f"Error parsing request submitted_at for user profile '{submitted_at_val}': {e_parse}")
                        req_dict['submitted_at'] = None
        else: req_dict['submitted_at'] = None
        requests_made_processed.append(req_dict)

    return render_template('admin_user_profile.html',
                           target_user=user,
                           messages_sent=messages_sent_processed,
                           requests_made=requests_made_processed)


@app.template_filter()
@pass_eval_context
def nl2br(eval_ctx, value):
    if not value: return ""
    br = Markup("<br>\n")
    str_value = str(value) if not isinstance(value, str) else value
    processed_value = str_value
    if eval_ctx.autoescape:
        processed_value = escape(str_value)
    result = processed_value.replace('\n', br)
    return Markup(result)


# --- Main Execution ---
if __name__ == '__main__':
    db_path = app.config['DATABASE']
    instance_folder_exists = os.path.exists(app.instance_path)
    db_file_exists = os.path.exists(db_path)

    if not instance_folder_exists:
        try: os.makedirs(app.instance_path, exist_ok=True)
        except OSError as e: print(f"Error creating instance folder: {e}")
            
    if not db_file_exists or os.path.getsize(db_path) == 0:
        with app.app_context():
            print("Database not found or empty. Initializing...")
            try:
                init_db()
                print(f"Database initialized at {db_path}")
            except Exception as e_init:
                print(f"Error during database initialization: {e_init}")

    app.run(debug=True)