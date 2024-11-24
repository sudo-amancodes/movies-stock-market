import os
import flask
import flask_login
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

from src.models import User, db, Role
from dotenv import load_dotenv

# Comment this if you are using environment variables in your code instead of in a .env file (not recommended)
# def create_app():
#     app = flask.Flask(__name__)

#     app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
#     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#     app.secret_key = os.getenv("SECRET_KEY")
#     db.init_app(app)

#     DB_USER = os.getenv('DB_USER', 'postgres')  # Replace with your default or env variable
#     DB_PASS = os.getenv('DB_PASS', '2327')  # Replace with your default or env variable
#     DB_HOST = os.getenv('DB_HOST', 'localhost')  # Replace with your DB host
#     DB_PORT = os.getenv('DB_PORT', '5432')  # Replace with the port your DB is running on
#     DB_NAME = os.getenv('DB_NAME', 'postgres')  # Replace with your actual DB name

#     return app

# Comment this if you are using environment variables a .env file intead of in your code (recommended)
def create_app():
    app = flask.Flask(__name__)
    
    load_dotenv()

    DB_USER = os.getenv('DB_USER')
    DB_PASS = os.getenv('DB_PASS')
    DB_HOST = os.getenv('DB_HOST')
    DB_PORT = os.getenv('DB_PORT')
    DB_NAME = os.getenv('DB_NAME')

    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.secret_key = os.getenv("SECRET_KEY")
    db.init_app(app)

    return app


app = create_app()

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = ''

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  

# Create tables if they do not exist
with app.app_context():
    db.create_all()
    print("Tables created!")

with app.app_context():
    if not Role.query.filter_by(name="User").first():
        db.session.add(Role(name="User"))
    if not Role.query.filter_by(name="Movie Studio").first():
        db.session.add(Role(name="Movie Studio"))
    db.session.commit()


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.get('/')
@login_required
def index():
    return render_template('index.html')

@app.get('/register_page_user')
def register_page():
    return render_template('register.html')

@app.post('/register')
def register():
    role = request.form.get('role')
    password = request.form.get('password')
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')

    if role == 'User':
        # Collect user-specific fields
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')

        # Ensure the username is unique
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('login_page'))
 

        # Create a new user
        new_user = User(first_name=first_name, last_name=last_name, username=username, password=hashed_password)

    elif role == 'Movie Studio':
        # Collect studio-specific fields
        studio_name = request.form.get('studio_name')

        # Ensure the studio name is unique
        if User.query.filter_by(studio_name=studio_name).first():
            flash('Studio name already exists.', 'danger')
            return redirect(url_for('login_page'))
 

        # Create a new studio
        new_user = User(studio_name=studio_name, password=hashed_password)

    else:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('register_page'))
 

    # Assign role to the new user
    selected_role = Role.query.filter_by(name=role).first()
    if not selected_role:
        selected_role = Role(name=role)
        db.session.add(selected_role)
        db.session.commit()

    new_user.roles.append(selected_role)
    db.session.add(new_user)
    db.session.commit()

    flash(f'Registration successful as a {role}. Please log in.', 'success')
    return redirect(url_for('login'))



@app.get('/login')
def login_page():
    return render_template('login.html')

@app.post('/login')
def login():
    role = request.form.get('role')  # Get the selected role
    username = request.form.get('username')
    password = request.form.get('password')

    # Determine whether to authenticate as a user or a studio
    if role == 'User':
        user = User.query.filter_by(username=username).first()  # Normal user
    elif role == 'Movie Studio':
        user = User.query.filter_by(studio_name=username).first()  # Movie studio
    else:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('login_page'))

    # Check password and log in the user
    if user and check_password_hash(user.password, password):
        login_user(user)
        flash('Login successful!', 'success')
        return redirect(url_for('index'))
    else:
        flash('Invalid username/studio name or password.', 'danger')
        return redirect(url_for('login_page'))


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
    
@app.post('/update_profile')
@login_required
def update_profile():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    username = request.form.get('username')

    # Ensure username is unique
    existing_user = User.query.filter_by(username=username).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Username already exists. Please choose another.', 'danger')
        return redirect(url_for('profile'))

    # Update user details
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.username = username
    db.session.commit()

    flash('Profile updated successfully.', 'success')
    return redirect(url_for('profile'))


app.config['TEMPLATES_AUTO_RELOAD'] = True

if __name__ == '__main__':
    app.run(debug=True)
