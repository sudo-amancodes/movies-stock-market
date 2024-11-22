import os
import flask
import flask_login
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

app = flask.Flask(__name__)

# Environment variables for database configuration
DB_USER = os.getenv('DB_USER', 'postgres')  # Replace with your default or env variable
DB_PASS = os.getenv('DB_PASS', '2327')  # Replace with your default or env variable
DB_HOST = os.getenv('DB_HOST', 'localhost')  # Replace with your DB host
DB_PORT = os.getenv('DB_PORT', '5432')  # Replace with the port your DB is running on
DB_NAME = os.getenv('DB_NAME', 'postgres')  # Replace with your actual DB name

# Set up the SQLAlchemy URI
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv("SECRET_KEY", 'your_secret_key')  # Change to a secure key

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Load user from the database

# Allowed file extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Define the User class
class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __init__(self, first_name, last_name, username, password):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User {self.username}>'

@app.get('/')
@login_required
def index():
    return render_template('index.html')

@app.get('/register_page_user')
def register_page():
    return render_template('register.html')

@app.post('/register')
def register():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')
    password = request.form.get('password')

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists.', 'danger')
        return redirect(url_for('login_page'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')
    
    new_user = User(first_name=first_name, last_name=last_name, username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful. Please log in.', 'success')
    return redirect(url_for('login'))

@app.get('/login')
def login_page():
    return render_template('login.html')

@app.post('/login')
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.get('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login_page'))

@app.get('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.post('/update_profile_pic')
@login_required
def update_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('profile'))

    file = request.files['profile_pic']
    
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('profile'))

    if file and allowed_file(file.filename):  
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.root_path, 'static/profile_pics', filename)
        file.save(filepath)

        current_user.profile_picture = filename
        db.session.commit()

        flash('Profile picture updated!', 'success')
        return redirect(url_for('profile'))
    else:
        flash('Invalid file type', 'danger')
        return redirect(url_for('profile'))

# Enable auto-reloading of templates
app.config['TEMPLATES_AUTO_RELOAD'] = True

if __name__ == '__main__':
    app.run(debug=True)
