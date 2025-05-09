# app.py
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import click # For CLI commands
from datetime import datetime # For timestamp in footer
from jinja2 import pass_eval_context # For custom filter
from markupsafe import Markup, escape # For custom filter

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['DATABASE'] = os.path.join(app.instance_path, 'users.db')

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
        g.user = db.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()

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
        # ... (admin logic remains the same) ...
        db = get_db()
        all_users = db.execute('SELECT id, username, is_admin FROM users ORDER BY username').fetchall()
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
        db = get_db()
        user_requests_raw = db.execute(
            "SELECT id, request_type, details, status, submitted_at FROM requests WHERE user_id = ? ORDER BY submitted_at DESC",
            (g.user['id'],)
        ).fetchall()

        user_requests_processed = []
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

        return render_template('dashboard_user.html', user_requests=user_requests_processed)

@app.route('/logout')
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
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        db = get_db()
        error = None

        if not username: error = 'Username is required.'
        elif not password: error = 'Password is required.'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            error = f"User {username} already exists."

        if error is None:
            db.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                       (username, generate_password_hash(password), 1 if is_admin else 0))
            db.commit()
            flash(f'User {username} created successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash(error, 'error')
    return render_template('admin_user_form.html', action="Create", user=None) # Pass user=None for consistency

@app.route('/admin/users/update/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_update_user(user_id):
    db = get_db()
    user_to_update = db.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_to_update:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        query_parts = ["is_admin = ?"]
        params = [1 if is_admin else 0]

        if new_password:
            query_parts.append("password_hash = ?")
            params.append(generate_password_hash(new_password))
        
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(query_parts)} WHERE id = ?"
        
        db.execute(query, tuple(params))
        db.commit()
        flash(f'User {user_to_update["username"]} updated.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('admin_user_form.html', action="Update", user=user_to_update)

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
@app.route('/messages/send', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        subject = request.form['subject']
        body = request.form['body']
        error = None
        if not subject: error = "Subject is required."
        elif not body: error = "Message body is required."

        if error is None:
            db = get_db()
            db.execute('INSERT INTO messages (sender_id, subject, body) VALUES (?, ?, ?)',
                       (g.user['id'], subject, body))
            db.commit()
            flash('Message sent to admin successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash(error, 'error')
    return render_template('send_message.html', prefill_subject="")

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

    messages_processed = []
    for msg_row in messages_raw:
        # Convert the dictionary-like Row object to a mutable dictionary
        msg_dict = dict(msg_row)
        # Assuming the timestamp from SQLite is in 'YYYY-MM-DD HH:MM:SS' format
        # Adjust the format string if your SQLite stores it differently
        try:
            if isinstance(msg_dict['timestamp'], str): # Check if it's a string
                 # The format string below assumes microseconds might be present due to some SQLite versions/drivers
                 # Try this first:
                dt_obj = datetime.strptime(msg_dict['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            elif isinstance(msg_dict['timestamp'], datetime): # Already a datetime object
                dt_obj = msg_dict['timestamp']
            else: # If it's neither, perhaps log an error or handle as an unknown format
                dt_obj = None # Or a default datetime
        except ValueError:
            # If the first format fails (e.g., no microseconds), try without:
            try:
                if isinstance(msg_dict['timestamp'], str):
                    dt_obj = datetime.strptime(msg_dict['timestamp'], '%Y-%m-%d %H:%M:%S')
                else:
                    dt_obj = msg_dict['timestamp'] # Or handle as above
            except ValueError as e:
                app.logger.error(f"Error parsing timestamp string '{msg_dict['timestamp']}': {e}")
                dt_obj = None # Or set to the original string to display as is, or a default datetime

        msg_dict['timestamp'] = dt_obj # Replace the string with the datetime object
        messages_processed.append(msg_dict)

    return render_template('admin_view_messages.html', messages=messages_processed)

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

    if request.method == 'POST':
        actual_request_type = request.form['request_type']
        details = request.form['details']
        error = None

        if not details: error = "Details for the request are required."

        if error is None:
            db = get_db()
            db.execute('INSERT INTO requests (user_id, request_type, details) VALUES (?, ?, ?)',
                       (g.user['id'], actual_request_type, details))
            db.commit()
            flash(f'{actual_request_type.capitalize()} request submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash(error, 'error')

    form_title = ""
    details_label = ""
    if request_type == 'payslip':
        form_title = "Request Payslip"
        details_label = "Month/Year (e.g., March 2024)"
    elif request_type == 'vacation':
        form_title = "Request Vacation"
        details_label = "Start Date, End Date, and Reason"
    else:
        flash("Invalid request type.", "error")
        return redirect(url_for('dashboard'))

    return render_template('new_request_form.html',
                           request_type=request_type,
                           form_title=form_title,
                           details_label=details_label)

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