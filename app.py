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
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads') # Store uploads in instance/uploads
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx'}
app.config['UPLOAD_FOLDER'] = os.path.join(app.instance_path, 'uploads')


# Define department options globally or pass from route
DEPARTMENT_CHOICES = ["Human Resources", "IT", "Marketing", "Sales", "Operations", "Finance", "Workers"]
GENDER_CHOICES = ["Male", "Female", "Other", "Prefer not to say"]


# --- Database Helper Functions ---
def get_db():
    if 'db' not in g:
        try:
            os.makedirs(app.instance_path)
        except OSError:
            pass
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
    try:
        # val is bytes, so decode first
        return datetime.fromisoformat(val.decode())
    except (ValueError, AttributeError):
        # Handle cases where val might already be a datetime or None, or invalid format
        # This part might need adjustment based on exact string formats from your DB
        try: # Try common SQLite format if fromisoformat fails
            return datetime.strptime(val.decode(), "%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, AttributeError):
            try:
                return datetime.strptime(val.decode(), "%Y-%m-%d %H:%M:%S")
            except (ValueError, AttributeError):
                return None # Or raise an error, or return the original string
# Ensure upload folder exists
try:
    os.makedirs(app.config['UPLOAD_FOLDER'])
except OSError:
    pass # Folder already exists

def allowed_file(filename):
    print(f"--- Debug: allowed_file called with filename: '{filename}'") # DEBUG
    has_dot = '.' in filename
    print(f"--- Debug: Filename has dot: {has_dot}") # DEBUG
    if not has_dot:
        return False
    ext_parts = filename.rsplit('.', 1)
    print(f"--- Debug: rsplit result: {ext_parts}") # DEBUG
    if len(ext_parts) < 2: # Should not happen if has_dot is true, but good check
        print(f"--- Debug: rsplit did not produce enough parts for filename '{filename}'") # DEBUG
        return False
    ext = ext_parts[1].lower()
    print(f"--- Debug: Extracted extension: '{ext}'") # DEBUG
    is_allowed = ext in ALLOWED_EXTENSIONS
    print(f"--- Debug: Is extension '{ext}' in ALLOWED_EXTENSIONS? {is_allowed}") # DEBUG
    return is_allowed


sqlite3.register_adapter(datetime, adapt_datetime_iso)
sqlite3.register_converter("DATETIME", convert_datetime_iso) # Use with detect_types
sqlite3.register_converter("timestamp", convert_datetime_iso) # Common alternative name


# --- Authentication Decorators ---
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if not g.user or not g.user['is_admin']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))
        return view(**kwargs)
    return wrapped_view

# --- Load Logged-in User ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        db = get_db()
        # Added full_name, gender, department to g.user for potential use
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
    if g.user:
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
            except db.IntegrityError:
                error = f"User '{username}' is already registered (database integrity error)."
            except Exception as e:
                app.logger.error(f"Registration error: {e}")
                error = "An unexpected error occurred during registration."
        
        if error:
            flash(error, 'error')
        # Re-render register page on error to show flashed messages and retain form data if desired
        return render_template('register.html') 

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if g.user:
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
        # On login failure, redirect to index (where login form is) or dedicated login page
        return redirect(url_for('index')) 

    return render_template('login.html') # For GET request to /login

@app.route('/dashboard')
@login_required
def dashboard():
    if g.user['is_admin']:
        db = get_db()
        all_users = db.execute(
            'SELECT id, username, is_admin, full_name, gender, department FROM users ORDER BY username'
        ).fetchall()
        unread_messages_count = db.execute(
            'SELECT COUNT(id) FROM messages WHERE is_read = 0'
        ).fetchone()[0]
        pending_requests_count = db.execute(
            "SELECT COUNT(id) FROM requests WHERE status = 'pending'"
        ).fetchone()[0]
        return render_template('dashboard_admin.html',
                               all_users=all_users,
                               unread_messages_count=unread_messages_count,
                               pending_requests_count=pending_requests_count)
    else:
        # This is the part for the regular user
        db = get_db()
        user_requests_raw = db.execute(
            """SELECT id, request_type, details, status, submitted_at, admin_notes
               FROM requests
               WHERE user_id = ?
               ORDER BY submitted_at DESC""",
            (g.user['id'],)
        ).fetchall()

        user_requests_processed = []
        if user_requests_raw:
            for req_row in user_requests_raw:
                req_dict = dict(req_row)
                try:
                    if isinstance(req_dict['submitted_at'], str):
                        dt_obj = datetime.strptime(req_dict['submitted_at'], '%Y-%m-%d %H:%M:%S.%f')
                    elif isinstance(req_dict['submitted_at'], datetime):
                        dt_obj = req_dict['submitted_at']
                    else:
                        dt_obj = None
                except ValueError:
                    try:
                        if isinstance(req_dict['submitted_at'], str):
                            dt_obj = datetime.strptime(req_dict['submitted_at'], '%Y-%m-%d %H:%M:%S')
                        else:
                            dt_obj = req_dict['submitted_at']
                    except ValueError as e:
                        app.logger.error(f"Error parsing user_request submitted_at string '{req_dict['submitted_at']}': {e}")
                        dt_obj = None
                req_dict['submitted_at'] = dt_obj
                user_requests_processed.append(req_dict)

        return render_template('dashboard_user.html', user_requests=user_requests_processed) # <<< ENSURE THIS RETURN IS HERE

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# --- Admin User Management Routes ---
@app.route('/admin/users/create', methods=['GET', 'POST']) # This line defines the route
@login_required
@admin_required
def admin_create_user(): # This function name is the endpoint 'admin_create_user'
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password') # No strip, password can have spaces
        is_admin = 'is_admin' in request.form
        full_name = request.form.get('full_name', '').strip()
        gender = request.form.get('gender')
        department = request.form.get('department')
        
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password: # Password is required for new user
            error = 'Password is required.'
        elif not full_name:
            error = 'Full Name is required.'
        elif gender and gender not in GENDER_CHOICES: # Validate against choices
            error = 'Invalid gender selected.'
        elif department and department not in DEPARTMENT_CHOICES: # Validate against choices
            error = 'Invalid department selected.'
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
                return redirect(url_for('dashboard')) # Or wherever your admin user list is
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error creating user: {e}")
                error = "An unexpected error occurred while creating the user."
        
        # If error occurred, flash it and re-render the form (values will be repopulated by request.form in template)
        if error:
            flash(error, 'error')
    
    # For GET request or if POST had an error, pass choices and form data to template
    # request.form will be empty on GET, but will have submitted values on POST error
    return render_template('admin_user_form.html',
                           action="Create",
                           user=None, # No existing user data for create form
                           department_choices=DEPARTMENT_CHOICES,
                           gender_choices=GENDER_CHOICES,
                           # Pass request.form to help repopulate fields on error
                           form_data=request.form if request.method == 'POST' else {})

@app.route('/admin/users/update/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    db = get_db()
    # Fetch all relevant fields for the user being updated
    user_to_update = db.execute(
        'SELECT id, username, is_admin, full_name, gender, department FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    if not user_to_update:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard')) # Or admin user list page

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
        # Username change is typically not allowed or handled with more care due to uniqueness
        # current_username = request.form.get('username')
        # if user_to_update['username'] != current_username and \
        #    db.execute('SELECT id FROM users WHERE username = ? AND id != ?', (current_username, user_id)).fetchone():
        #     error = f"Username {current_username} already taken."


        if error is None:
            query_parts = ["is_admin = ?", "full_name = ?", "gender = ?", "department = ?"]
            params = [1 if is_admin else 0, full_name, gender, department]

            if new_password:
                query_parts.append("password_hash = ?")
                params.append(generate_password_hash(new_password))
            
            params.append(user_id) # For the WHERE clause
            query = f"UPDATE users SET {', '.join(query_parts)} WHERE id = ?"
            
            try:
                db.execute(query, tuple(params))
                db.commit()
                flash(f'User {user_to_update["username"]} updated successfully.', 'success')
                return redirect(url_for('dashboard')) # Or admin user list page
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error updating user: {e}")
                error = "An unexpected error occurred while updating the user."

        if error:
            flash(error, 'error')
    
    # For GET request or if POST had an error
    return render_template('admin_user_form.html',
                           action="Update",
                           user=user_to_update,
                           department_choices=DEPARTMENT_CHOICES,
                           gender_choices=GENDER_CHOICES)


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if g.user['id'] == user_id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('dashboard'))
    
    db = get_db()
    # Consider what to do with messages/requests from/to this user (cascade, nullify, restrict)
    # For simplicity, let's delete related items. Add FOREIGN KEY ON DELETE CASCADE in schema for robust handling.
    db.execute('DELETE FROM messages WHERE sender_id = ?', (user_id,))
    db.execute('DELETE FROM requests WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User and their related data deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

# --- Messaging Routes ---

# app.py

# ... (imports and other setup) ...

@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        print("--- Debug: POST request received for /messages/send ---") # DEBUG

        # Attempt to get form data
        try:
            subject = request.form['subject']
            body = request.form['body']
            print(f"--- Debug: Subject from form: '{subject}'") # DEBUG
            print(f"--- Debug: Body from form: '{body}' (first 50 chars: {body[:50]})") # DEBUG
        except KeyError as ke:
            app.logger.error(f"KeyError accessing form data: {ke}")
            flash(f"Missing form field: {ke}. Please ensure all fields are filled.", "error")
            return render_template('send_message.html', prefill_subject=request.form.get('subject', '')) # Re-render with error

        attachment = request.files.get('attachment')
        error = None # Initialize error AFTER getting subject and body

        # Removed redundant subject/body checks here as KeyError above would handle missing fields
        # if not subject: error = "Subject is required." 
        # elif not body: error = "Message body is required."

        stored_filename = None
        original_filename_for_db = None

        if attachment and attachment.filename:
            print(f"--- Debug: Received attachment.filename: '{attachment.filename}'")
            original_filename_from_secure = secure_filename(attachment.filename)
            print(f"--- Debug: secure_filename output: '{original_filename_from_secure}'")

            if not original_filename_from_secure:
                error = "Invalid attachment filename (was sanitized to empty)."
            elif allowed_file(original_filename_from_secure):
                original_filename_for_db = original_filename_from_secure
                print(f"--- Debug: File type IS allowed. original_filename_for_db: '{original_filename_for_db}'")
                if '.' in original_filename_for_db:
                    file_ext = original_filename_for_db.rsplit('.', 1)[1].lower()
                else:
                    file_ext = ""
                print(f"--- Debug: Final file_ext for stored_filename: '{file_ext}'")

                if file_ext or not error: 
                    unique_id = uuid.uuid4().hex
                    stored_filename = f"{unique_id}.{file_ext}" if file_ext else f"{unique_id}"
                    try:
                        attachment.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                        print(f"--- Debug: File saved as {stored_filename}") # DEBUG
                    except Exception as e:
                        app.logger.error(f"File save error: {e}")
                        error = "Could not save attachment. Please try again."
                        stored_filename = None
                        original_filename_for_db = None
            else:
                error = "Invalid file type or filename. Allowed types are: " + ", ".join(sorted(list(ALLOWED_EXTENSIONS)))
        
        print(f"--- Debug: Before DB operations. Error: {error}, Subject: '{subject}', Body (len): {len(body) if 'body' in locals() else 'N/A'}") # DEBUG

        if error is None:
            db = get_db()
            cursor = db.cursor()
            try:
                print("--- Debug: Attempting to insert into messages table ---") # DEBUG
                # Ensure subject and body are indeed defined and accessible here
                cursor.execute('INSERT INTO messages (sender_id, subject, body) VALUES (?, ?, ?)',
                               (g.user['id'], subject, body)) # These must be defined
                message_id = cursor.lastrowid
                print(f"--- Debug: Message inserted with ID: {message_id}") # DEBUG

                if stored_filename and original_filename_for_db and message_id:
                    print("--- Debug: Attempting to insert into attachments table ---") # DEBUG
                    cursor.execute('INSERT INTO attachments (message_id, original_filename, stored_filename) VALUES (?, ?, ?)',
                                   (message_id, original_filename_for_db, stored_filename))
                    print("--- Debug: Attachment inserted.") # DEBUG
                
                db.commit()
                print("--- Debug: DB commit successful.") # DEBUG
                flash('Message sent successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Message/Attachment DB error: {e}")
                # The print below helps confirm if 'subject' was undefined when the exception occurred
                print(f"--- Debug: Exception in DB block. Subject defined? {'subject' in locals()}. Body defined? {'body' in locals()}") # DEBUG
                error = "An error occurred while sending the message."
                if stored_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)):
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
                    except Exception as del_e:
                        app.logger.error(f"Error deleting orphaned file {stored_filename}: {del_e}")
        
        if error:
            flash(error, 'error')

    return render_template('send_message.html', prefill_subject=request.form.get('subject', '')) # Use request.form.get for prefill
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
        # Timestamp conversion logic (as implemented before)
        try:
            if isinstance(msg_dict['timestamp'], str):
                dt_obj = datetime.strptime(msg_dict['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            elif isinstance(msg_dict['timestamp'], datetime):
                dt_obj = msg_dict['timestamp']
            else: dt_obj = None
        except ValueError:
            try:
                if isinstance(msg_dict['timestamp'], str): dt_obj = datetime.strptime(msg_dict['timestamp'], '%Y-%m-%d %H:%M:%S')
                else: dt_obj = msg_dict['timestamp']
            except ValueError as e:
                app.logger.error(f"Error parsing message timestamp string '{msg_dict['timestamp']}': {e}")
                dt_obj = None
        msg_dict['timestamp'] = dt_obj
        
        # Fetch attachments for this message
        attachments = db.execute('''
            SELECT id, original_filename, stored_filename
            FROM attachments
            WHERE message_id = ?
        ''', (msg_dict['id'],)).fetchall()
        msg_dict['attachments'] = attachments
        processed_messages.append(msg_dict)

    return render_template('admin_view_messages.html', messages=processed_messages)

# Route to serve uploaded files (for admins to download)
@app.route('/uploads/<filename>')
@login_required
@admin_required # Or adjust permission as needed
def uploaded_file(filename):
    # Add extra security checks here if necessary (e.g., check if user has permission for this specific file)
    # For now, only admins can access any file by its stored_filename
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False) # as_attachment=True forces download
    except FileNotFoundError:
        flash("File not found.", "error")
        return redirect(url_for('admin_view_messages'))


@app.route('/admin/messages/mark_read/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def admin_mark_message_read(message_id):
    db = get_db()
    db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,))
    db.commit()
    flash('Message marked as read.', 'success')
    return redirect(url_for('admin_view_messages'))

# --- User Request Routes (Payslip, Vacation) ---

@app.route('/request/new', methods=['GET', 'POST'])
@login_required
def new_request_form():
    request_type = request.args.get('type', 'payslip')
    error = None

    if request.method == 'POST':
        actual_request_type = request.form['request_type']
        details = ""

        if actual_request_type == 'payslip':
            month = request.form.get('payslip_month')
            year = request.form.get('payslip_year')
            if month and year:
                details = f"Payslip for: {month} {year}"
            else:
                if not error: error = "Please select both month and year for the payslip request."
        
        elif actual_request_type == 'vacation':
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            reason = request.form.get('vacation_reason', '').strip() # Optional reason field

            if not start_date_str or not end_date_str:
                if not error: error = "Please select both a start and end date for your vacation."
            else:
                try:
                    # Convert to datetime objects for validation
                    start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d')
                    end_date_obj = datetime.strptime(end_date_str, '%Y-%m-%d')

                    if end_date_obj < start_date_obj:
                        if not error: error = "End date cannot be before the start date."
                    else:
                        # Calculate duration (optional, but good for details)
                        duration = (end_date_obj - start_date_obj).days + 1
                        details = f"Vacation: {start_date_obj.strftime('%b %d, %Y')} to {end_date_obj.strftime('%b %d, %Y')} ({duration} day{'s' if duration != 1 else ''})."
                        if reason:
                            details += f" Reason: {reason}"
                except ValueError:
                    if not error: error = "Invalid date format submitted. Please use the calendar."
        else: # Other request types (if any)
            details = request.form.get('details', '').strip()

        # Centralized validation for 'details' (after specific type processing)
        if not details and not error: # If details string is still empty and no prior error
            if actual_request_type == 'payslip': # This condition might be redundant now
                 error = "Month and Year are required for the payslip request."
            elif actual_request_type == 'vacation': # This condition might be redundant now
                 error = "Start and End dates are required for the vacation request."
            else:
                 error = "Details for the request are required."
        
        # ... (rest of POST logic: DB insertion, flash messages) ...
        if error is None:
            db = get_db()
            try:
                db.execute('INSERT INTO requests (user_id, request_type, details) VALUES (?, ?, ?)',
                           (g.user['id'], actual_request_type, details))
                db.commit()
                flash(f'{actual_request_type.capitalize()} request submitted successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.rollback()
                app.logger.error(f"Error inserting request into DB: {e}")
                error = "An unexpected error occurred while submitting your request. Please try again."
        
        if error:
            flash(error, 'error')

    # --- GET Request or re-render after POST error ---
    form_title = ""
    details_label = "" # Not used for payslip/vacation directly anymore
    details_placeholder = "" # Not used for payslip/vacation directly anymore
    icon_class = "fa-clipboard-list"
    
    current_year = datetime.utcnow().year
    years_for_select = list(range(current_year, current_year - 6, -1))
    months_for_select = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]

    if request_type == 'payslip':
        form_title = "Request Payslip"
        icon_class = "fa-file-invoice-dollar"
    elif request_type == 'vacation':
        form_title = "Request Vacation Time"
        icon_class = "fa-plane-departure"
        # details_label = "Reason (Optional)" # Label for the reason textarea
        # details_placeholder = "e.g., Annual leave, Family event"
    else:
        flash("Invalid request type specified.", "error")
        return redirect(url_for('dashboard'))

    return render_template('new_request_form.html',
                           request_type=request_type,
                           form_title=form_title,
                           # details_label=details_label, # Pass if you have a general details field
                           # details_placeholder=details_placeholder,
                           icon_class=icon_class,
                           years_for_select=years_for_select, # For payslip
                           months_for_select=months_for_select, # For payslip
                           error=error)

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
        try:
            if isinstance(req_dict['submitted_at'], str):
                dt_obj = datetime.strptime(req_dict['submitted_at'], '%Y-%m-%d %H:%M:%S.%f')
            elif isinstance(req_dict['submitted_at'], datetime):
                dt_obj = req_dict['submitted_at']
            else:
                dt_obj = None
        except ValueError:
            try:
                if isinstance(req_dict['submitted_at'], str):
                    dt_obj = datetime.strptime(req_dict['submitted_at'], '%Y-%m-%d %H:%M:%S')
                else:
                    dt_obj = req_dict['submitted_at']
            except ValueError as e:
                app.logger.error(f"Error parsing submitted_at string '{req_dict['submitted_at']}': {e}")
                dt_obj = None
        req_dict['submitted_at'] = dt_obj
        requests_processed.append(req_dict)

    return render_template('admin_view_requests.html', requests=requests_processed)

@app.route('/admin/requests/update_status/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_request_status(request_id):
    new_status = request.form['status']
    admin_notes = request.form.get('admin_notes', '')
    db = get_db()

    if new_status not in ['pending', 'approved', 'rejected']:
        flash("Invalid status.", "error")
    else:
        db.execute('UPDATE requests SET status = ?, admin_notes = ? WHERE id = ?',
                   (new_status, admin_notes, request_id))
        db.commit()
        flash('Request status updated.', 'success')
    return redirect(url_for('admin_view_requests'))
@app.template_filter()
@pass_eval_context
def nl2br(eval_ctx, value):
    """Converts newlines in a string to HTML <br /> tags."""
    if not value: # Handle None or empty string gracefully
        return ""
    # Escape the original value to prevent XSS if it's not already safe
    # then replace \n with <br>. Markup ensures the <br> is not escaped.
    br = Markup("<br>\n")
    result = escape(value).replace('\n', br)
    return Markup(result)


# --- Main Execution ---
if __name__ == '__main__':
    # One-time database initialization if it doesn't exist or is empty
    db_path = app.config['DATABASE']
    instance_folder_exists = os.path.exists(app.instance_path)
    db_file_exists = os.path.exists(db_path)

    if not instance_folder_exists:
        try:
            os.makedirs(app.instance_path)
        except OSError as e:
            print(f"Error creating instance folder: {e}") # Should not happen if checking above
            
    if not db_file_exists or os.path.getsize(db_path) == 0:
        with app.app_context(): # We need app context to call get_db() and open_resource
            print("Database not found or empty. Initializing...")
            init_db()
            print(f"Database initialized at {db_path}")

    app.run(debug=True)