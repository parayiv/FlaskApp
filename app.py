# app.py
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps # For login_required decorator
from datetime import datetime

# --- App Configuration ---
app = Flask(__name__)
# It's crucial to set a secret key for session management and flashing messages.
# In a real app, use a strong, randomly generated key and store it securely.
app.config['SECRET_KEY'] = os.urandom(24) # Or 'your_very_secret_key'
# Define the path for the SQLite database.
# 'instance_relative_config=True' means the path is relative to the instance folder.
app.config['DATABASE'] = os.path.join(app.instance_path, 'users.db')

# --- Database Helper Functions ---
def get_db():
    """Connects to the specific database."""
    if 'db' not in g:
        # Ensure the instance folder exists
        try:
            os.makedirs(app.instance_path)
        except OSError:
            pass # It might already exist
        g.db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row # Access columns by name
    return g.db

def close_db(e=None):
    """Closes the database connection."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database using schema.sql."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    print("Initialized the database.")

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

# Register database functions with the Flask app
app.teardown_appcontext(close_db) # Call close_db when app context ends
# app.cli.add_command(init_db_command) # Add 'flask init-db' command -> Requires `click` to be installed

# --- Authentication Decorator ---
def login_required(view):
    """
    View decorator that redirects anonymous users to the login page.
    """
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

# --- Load Logged-in User ---
@app.before_request
def load_logged_in_user():
    """
    If a user_id is stored in the session, load the user object from
    the database and make it available in `g.user`.
    """
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

# --- Routes ---
# --- Routes ---
@app.route('/', methods=('GET', 'POST')) # Allow POST if you intend to handle form submission here
def index():
    # If handling form submissions directly on index:
    # if request.method == 'POST':
    #     if 'register_submit' in request.form: # Check which form was submitted
    #         # Handle registration logic (similar to /register route)
    #         # ...
    #         pass
    #     elif 'login_submit' in request.form:
    #         # Handle login logic (similar to /login route)
    #         # ...
    #         pass

    # For now, let's keep it simple: index just renders the page with forms
    # The forms themselves will POST to /register and /login
    return render_template('index.html')

@app.route('/register', methods=('GET', 'POST'))
def register():
    if g.user:
        flash("You are already logged in.", "info")
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
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, generate_password_hash(password))
                )
                db.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login')) # Or redirect to index if login form is there
            except db.IntegrityError: # Should be caught by the check above, but good practice
                error = f"User '{username}' is already registered (database integrity)."
            except Exception as e:
                error = f"An error occurred: {e}"


        if error: # Flash error if any occurred
            flash(error, 'error')
        # If registration fails, we re-render the register page (or index page if forms are combined)
        # To keep it simple, we'll redirect to index, and errors will be flashed there.
        # Or, you could render 'register.html' specifically if you want to keep it separate.
        return redirect(url_for('index')) # Or render_template('register.html') if you prefer

    # If GET request for /register, or if POST failed and we want to show a dedicated register page.
    # For your request, the forms are on index.html, so a direct GET to /register might be less common
    # unless linked explicitly. We can make it redirect to index or show its own form.
    # For now, let's assume if someone GETs /register, they see the register form there.
    return render_template('register.html') # This assumes you still want a dedicated /register page

@app.route('/login', methods=('GET', 'POST'))
def login():
    if g.user: # If user is already logged in, redirect them
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password_hash'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            flash(f'Welcome back, {user["username"]}!', 'success')
            # Handle 'next' parameter for redirecting after login
            next_url = request.args.get('next')
            if next_url:
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        
        flash(error, 'error')

    return render_template('login.html')

@app.route('/dashboard')
@login_required # Protect this route
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


# --- Main Execution ---
if __name__ == '__main__':
    # One-time database initialization if it doesn't exist
    # For production, use 'flask init-db' command
    db_path = app.config['DATABASE']
    if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        with app.app_context(): # We need app context to call get_db()
            init_db()
            print(f"Database created at {db_path}")

    app.run(debug=True)