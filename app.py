import os, flask, requests, json, flask_login
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from src.models import db, User, SoccerTeam, UserWatchlistTeams
from flask import request, jsonify, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename

from flask import request, jsonify, redirect, url_for, session, render_template

app = flask.Flask(__name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("DB_USER")}:{os.getenv("DB_PASS")}@{os.getenv("DB_HOST")}:{os.getenv("DB_PORT")}/{os.getenv("DB_NAME")}'
app.secret_key = os.getenv("SECRET_KEY")

db.init_app(app)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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


app.config['TEMPLATES_AUTO_RELOAD'] = True

if __name__ == '__main__':
    app.run(debug=True)