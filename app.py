# app.py - Backend using Flask and Flask-SQLAlchemy

import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, login_user, logout_user, login_required, current_user # For more robust auth
from werkzeug.security import generate_password_hash, check_password_hash
# For secure filenames if saving files to disk
from werkzeug.utils import secure_filename
import datetime

# --- App Configuration ---
app = Flask(__name__)
# Configure CORS to allow connections from GitHub Pages and local development
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://127.0.0.1:5000",
            "http://localhost:5000",
            "https://mandrusian.github.io",
            "http://mandrusian.github.io"
        ],
        "methods": ["GET", "POST", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Configure SQLite database
# Use an absolute path for the database file
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_change_this_in_production' # Needed for sessions/security

db = SQLAlchemy(app)

# --- File Upload Configuration ---
# Define directory to save uploaded files (needs to exist and be writeable)
# For a production app, use cloud storage (S3, GCS)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Create the upload folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Basic Session Management (replace with Flask-Login for robust auth) ---
# This is a simplified approach for demonstration
# You would initialize and configure Flask-Login here
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login' # Set the login view endpoint
# login_manager.login_message = 'Please log in to access this page.'
# login_manager.login_message_category = 'info'

# @login_manager.user_loader
# def load_user(user_id):
#      # In a real app, query the database for the user by ID
#      return UserDB.query.get(int(user_id))


# --- Database Models ---
class UserDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    threads = db.relationship('Thread', backref='author', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)

    # Required for Flask-Login UserMixin (add this in a real app)
    # @property
    # def is_authenticated(self):
    #      return True # Replace with real auth check
    #
    # @property
    # def is_active(self):
    #      return True
    #
    # @property
    # def is_anonymous(self):
    #      return False
    #
    # def get_id(self):
    #      return str(self.id)


    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('user_db.id'), nullable=False)

    posts = db.relationship('Post', backref='thread', lazy=True, cascade='all, delete-orphan') # Cascade delete posts

    def __repr__(self):
        return f'<Thread {self.title}>'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('user_db.id'), nullable=False)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), nullable=False)

    # Relationship to files (Optional: if storing file info with posts)
    files = db.relationship('File', backref='post', lazy=True, cascade='all, delete-orphan')


    def __repr__(self):
        return f'<Post {self.content[:20]}...>'

# Optional: Model for file metadata if not embedding in Post
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False) # Path on server or storage URL
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def __repr__(self):
        return f'<File {self.filename}>'


# --- Database Initialization ---
# Run this in a Python shell or add a command to create the database
# Example:
# from app import app, db
# with app.app_context():
#     db.create_all()


# --- User Registration Endpoint ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = UserDB.query.filter_by(username=username).first()
    if user:
        return jsonify({'message': 'Username already exists'}), 409

    # Hash the password before saving
    hashed_password = generate_password_hash(password)

    # Assign admin status based on username 'mandrusian'
    is_admin = username.lower() == 'mandrusian'
    # Check if 'mandrusian' account already exists if trying to create it
    if is_admin:
         existing_admin = UserDB.query.filter_by(username='mandrusian', is_admin=True).first()
         if existing_admin:
              return jsonify({'message': "'mandrusian' account already exists"}), 409


    new_user = UserDB(username=username, password_hash=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    print(f"New user registered: {username}, Admin: {is_admin}") # For demonstration

    return jsonify({'message': 'User registered successfully'}), 201

# --- User Login Endpoint ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return jsonify({'message': 'Please use POST method for login'}), 405
        
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = UserDB.query.filter_by(username=username).first()

    # Check hashed password
    if user and user.check_password(password):
        # --- Session Management ---
        # In a real application, use Flask-Login's login_user() or issue a token
        # For this basic example, we'll return user info (DO NOT SEND PASSWORD HASH)
        # login_user(user) # Example if using Flask-Login

        print(f"User logged in: {username}") # For demonstration
        return jsonify({'message': 'Login successful', 'username': user.username, 'is_admin': user.is_admin}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# --- User Logout Endpoint (Requires Session Management) ---
@app.route('/logout', methods=['POST'])
# @login_required # Example if using Flask-Login
def logout():
     # --- Session Management ---
     # In a real application, use Flask-Login's logout_user() or invalidate the token
     # For this basic example, we'll just return a success message
     # logout_user() # Example if using Flask-Login

     print(f"User logged out (simulated)") # For demonstration
     return jsonify({'message': 'Logged out successfully'}), 200

# --- Create Thread Endpoint ---
@app.route('/threads', methods=['POST'])
# @login_required # Requires authenticated user
def create_thread():
    # --- Authentication Required ---
    # In a real app, get the current user from the session/token
    # For this example, we'll need the frontend to send the username (INSECURE for real app)
    # Replace with: current_user = get_current_user() # using your auth system

    data = request.get_json()
    title = data.get('title')
    # Assuming frontend sends username (INSECURE)
    author_username = data.get('author_username')

    if not title or not author_username:
         return jsonify({'message': 'Title and author are required'}), 400

    author = UserDB.query.filter_by(username=author_username).first()
    if not author:
         # This indicates a problem if frontend is sending username of non-existent user
         return jsonify({'message': 'Author not found'}), 404


    new_thread = Thread(title=title, author=author, created_at=datetime.datetime.now())
    db.session.add(new_thread)
    db.session.commit()

    print(f"Thread created: '{title}' by {author_username}") # For demonstration
    return jsonify({'message': 'Thread created successfully', 'thread_id': new_thread.id}), 201

# --- Get Threads Endpoint ---
@app.route('/threads', methods=['GET'])
def get_threads():
    threads = Thread.query.all()
    threads_list = []
    for thread in threads:
        # Count posts for reply count
        reply_count = len(thread.posts)
        threads_list.append({
            'id': thread.id,
            'title': thread.title,
            'author': thread.author.username, # Access author username
            'created_at': thread.created_at.isoformat(),
            'reply_count': reply_count
        })

    # Sort threads by creation date, newest first
    threads_list.sort(key=lambda x: x['created_at'], reverse=True)


    return jsonify(threads_list), 200

# --- Get Posts for a Thread Endpoint ---
@app.route('/threads/<int:thread_id>/posts', methods=['GET'])
def get_posts_for_thread(thread_id):
    thread = Thread.query.get(thread_id)
    if not thread:
        return jsonify({'message': 'Thread not found'}), 404

    # Order posts by creation date
    posts = Post.query.filter_by(thread_id=thread_id).order_by(Post.created_at.asc()).all()
    posts_list = []
    for post in posts:
        # Fetch files associated with the post
        post_files_info = []
        for file in post.files:
             post_files_info.append({'filename': file.filename, 'url': file.filepath}) # Use filepath for URL


        posts_list.append({
            'id': post.id,
            'content': post.content,
            'author': post.author.username, # Access author username
            'created_at': post.created_at.isoformat(),
            'files': post_files_info
        })

    return jsonify(posts_list), 200


# --- Create Post (Reply to Thread) Endpoint ---
@app.route('/threads/<int:thread_id>/posts', methods=['POST'])
# @login_required # Requires authenticated user
def create_post(thread_id):
    # --- Authentication Required ---
    # In a real app, get the current user from the session/token
    # For this example, we'll need the frontend to send the username (INSECURE for real app)
    # Replace with: author = current_user

    thread = Thread.query.get(thread_id)
    if not thread:
        return jsonify({'message': 'Thread not found'}), 404

    # Use request.form for file uploads and other form data
    content = request.form.get('content')
    # Assuming frontend sends username with form data (INSECURE)
    author_username = request.form.get('author_username')
    files = request.files.getlist('files') # Get list of uploaded files

    if not content and not files:
         return jsonify({'message': 'Content or files are required'}), 400


    author = UserDB.query.filter_by(username=author_username).first()
    if not author:
         # This indicates a problem if frontend is sending username of non-existent user
         return jsonify({'message': 'Author not found'}), 404


    new_post = Post(content=content, author=author, thread=thread, created_at=datetime.datetime.now())
    db.session.add(new_post)
    db.session.commit() # Commit to get post ID before handling files

    # --- File Upload Handling ---
    # In a real application:
    # 1. Validate file types and sizes (important for security).
    # 2. Securely save files to cloud storage or a designated server directory.
    # 3. Create File DB entries linked to the new post.
    uploaded_files_info = []
    if files:
        print(f"Received {len(files)} file(s) for post {new_post.id}")
        for file in files:
            if file.filename:
                # Use secure_filename to sanitize filename (important!)
                filename = secure_filename(file.filename)
                # Define a path to save (e.g., uploads/post_id/filename)
                post_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(new_post.id))
                os.makedirs(post_upload_folder, exist_ok=True) # Create post-specific folder
                filepath_on_disk = os.path.join(post_upload_folder, filename)
                file.save(filepath_on_disk)

                # Create a URL path to access the file (e.g., /uploads/post_id/filename)
                file_url_path = os.path.join(app.config['UPLOAD_FOLDER'], str(new_post.id), filename)

                # Save file metadata to File model and link to new_post
                new_file = File(filename=filename, filepath=file_url_path, post=new_post)
                db.session.add(new_file)
                uploaded_files_info.append({'filename': filename, 'url': '/' + file_url_path.replace('\\', '/')}) # Use forward slashes for URL


        db.session.commit() # Commit file entries


    print(f"Post created in thread {thread_id} by {author_username}") # For demonstration
    return jsonify({'message': 'Post created successfully', 'post_id': new_post.id, 'files': uploaded_files_info}), 201


# --- Delete Post Endpoint ---
@app.route('/posts/<int:post_id>', methods=['DELETE'])
# @login_required # Requires authenticated user
def delete_post(post_id):
    # --- Authentication and Authorization Required ---
    # In a real app, get the current user from the session/token
    # Check if user is logged in and is either the author of the post OR an admin.
    # For this example, we'll need the frontend to send the username (INSECURE for real app)
    # Replace with: current_user = get_current_user()
    # logged_in_username = request.args.get('username') # Example of passing via query param (INSECURE)
    # is_admin = request.args.get('is_admin') == 'true' # Example of passing via query param (INSECURE)

    post = Post.query.get(post_id)
    if not post:
        return jsonify({'message': 'Post not found'}), 404

    # --- Secure Authorization Check ---
    # This is the critical part. The backend MUST verify the user's identity and permissions.
    # For this example, we'll simulate the check based on a hypothetical logged-in user
    # and admin status that you would get from your auth system (e.g., Flask-Login's current_user)
    # Replace with:
    # if not current_user or (current_user.id != post.author_id and not current_user.is_admin):
    #      return jsonify({'message': 'Unauthorized to delete this post'}), 403

    # For demonstration without real auth: Assume auth info is sent (DO NOT DO THIS IN REAL APP)
    logged_in_username = request.args.get('username') # Get username from query parameter (INSECURE)
    is_admin_str = request.args.get('is_admin') # Get is_admin from query parameter (INSECURE)
    is_admin = is_admin_str.lower() == 'true' if is_admin_str else False # Convert string to boolean

    # Find the user making the request (for the authorization check)
    requesting_user = UserDB.query.filter_by(username=logged_in_username).first()

    # Perform the authorization check based on the user from the database
    if not requesting_user or (requesting_user.id != post.author_id and not requesting_user.is_admin):
         return jsonify({'message': 'Unauthorized to delete this post'}), 403


    # If authorized: Delete associated files first (optional but good practice)
    for file in post.files:
         filepath_on_disk = os.path.join(basedir, file.filepath)
         if os.path.exists(filepath_on_disk):
              try:
                   os.remove(filepath_on_disk)
                   print(f"Deleted file on disk: {filepath_on_disk}")
              except OSError as e:
                   print(f"Error deleting file {filepath_on_disk}: {e}")

    # Delete post and associated file records from the database (cascade should handle File records)
    db.session.delete(post)
    db.session.commit()

    print(f"Post {post_id} deleted by {logged_in_username}.") # For demonstration
    return jsonify({'message': 'Post deleted successfully'}), 200

# --- File Serving Endpoint ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # --- Security Warning ---
    # Serve files securely. Werkzeug's send_from_directory helps prevent directory traversal attacks,
    # but ensure the UPLOAD_FOLDER is outside your application's source code if possible.
    # For a real app, consider more robust access control if files are private.
    try:
        # Correctly join the upload folder with the base directory
        upload_dir = os.path.join(basedir, app.config['UPLOAD_FOLDER'])
        return send_from_directory(upload_dir, filename)
    except FileNotFoundError:
        return jsonify({'message': 'File not found'}), 404


# --- Endpoint for Account Management Actions (Placeholders) ---
# These would require actual backend logic for updating/deleting users in the database
@app.route('/account/manage', methods=['POST'])
# @login_required
def manage_account():
    # --- Authentication Required ---
    # Get current user, handle requests to update password, etc.
    print("Manage account endpoint hit (placeholder)")
    return jsonify({'message': 'Account management not fully implemented in backend'}), 501

@app.route('/account/delete', methods=['DELETE'])
# @login_required
def delete_account():
     # --- Authentication Required ---
     # Get current user, delete user and their associated data from the database.
     print("Delete account endpoint hit (placeholder)")
     return jsonify({'message': 'Account deletion not fully implemented in backend'}), 501


if __name__ == '__main__':
    # --- Create Database Tables ---
    # This will create the database file and tables if they don't exist.
    # In a production app, use Flask-Migrate for database schema changes.
    with app.app_context():
        db.create_all()
        print("Database tables created (if they didn't exist).")

    # Run the Flask development server
    # In a production environment, use a production-ready web server like Gunicorn or uWSGI
    app.run(debug=True) # debug=True should ONLY be used for development 