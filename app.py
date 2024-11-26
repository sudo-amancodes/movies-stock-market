import os
import flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, redirect, url_for, session, render_template, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect  # Ensure CSRFProtect is imported

from src.models import Project, User, db, Role, Message, Follows

# Initialize Flask app and load environment variables
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

    migrate = Migrate(app, db)

    return app

app = create_app()

# Initialize CSRF Protection

# Initialize SocketIO with Flask-Login support
socketio = SocketIO(app, manage_session=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = ''

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  

# Create tables and ensure roles exist
with app.app_context():
    db.create_all()
    print("Tables created!")

    # Ensure roles exist
    if not Role.query.filter_by(name="User").first():
        db.session.add(Role(name="User"))
    if not Role.query.filter_by(name="Movie Studio").first():
        db.session.add(Role(name="Movie Studio"))
    db.session.commit()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.get('/user/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)

# In app.py

@app.get('/user/<int:user_id>/followers')
@login_required
def followers_list(user_id):
    user = User.query.get_or_404(user_id)
    followers = user.followers_users
    return render_template('followers_list.html', user=user, followers=followers)

@app.get('/user/<int:user_id>/following')
@login_required
def following_list(user_id):
    user = User.query.get_or_404(user_id)
    following = user.following_users
    return render_template('following_list.html', user=user, following=following)



# Route to delete a project
@app.post('/delete_project/<int:project_id>')
@login_required
def delete_project(project_id):
    if current_user.get_roles() != 'Movie Studio':
        flash('Only movie studios can delete projects.', 'danger')
        return redirect(url_for('profile'))

    project = Project.query.get_or_404(project_id)

    # Ensure the project belongs to the current user
    if project.studio_id != current_user.id:
        flash('You do not have permission to delete this project.', 'danger')
        return redirect(url_for('profile'))

    # Delete the project and its associated data
    db.session.delete(project)
    db.session.commit()

    flash(f'Project "{project.name}" deleted successfully.', 'success')
    return redirect(url_for('profile'))

# Route to create a project from profile
@app.post('/create_project_from_profile')
@login_required
def create_project_from_profile():
    if current_user.get_roles() != 'Movie Studio':
        flash('Only movie studios can create projects.', 'danger')
        return redirect(url_for('profile'))

    name = request.form.get('name')
    description = request.form.get('description')
    banner = request.files.get('banner')

    if not name or not description or not banner:
        flash('All fields are required.', 'danger')
        return redirect(url_for('profile'))

    if banner and allowed_file(banner.filename):
        filename = secure_filename(banner.filename)
        filepath = os.path.join(app.root_path, 'static/project_banners', filename)
        banner.save(filepath)

        # Save project
        project = Project(name=name, description=description, banner=filename, studio=current_user)
        db.session.add(project)
        db.session.commit()

        flash('Project created successfully!', 'success')
    else:
        flash('Invalid banner file type.', 'danger')

    return redirect(url_for('profile'))

# Route to create a project
@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if current_user.get_roles() != 'Movie Studio':
        flash('Only movie studios can create projects.', 'danger')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        banner = request.files.get('banner')

        # Validate fields
        if not name or not description or not banner:
            flash('All fields are required.', 'danger')
            return redirect(url_for('create_project'))

        # Save banner image
        if banner and allowed_file(banner.filename):
            filename = secure_filename(banner.filename)
            filepath = os.path.join(app.root_path, 'static/project_banners', filename)
            banner.save(filepath)

            # Create and save the project
            project = Project(name=name, description=description, banner=filename, studio=current_user)
            db.session.add(project)
            db.session.commit()
            flash('Project created successfully!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid banner file type.', 'danger')

    return render_template('create_project.html')

# Route to view project details
@app.get('/project/<int:project_id>')
@login_required
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project_details.html', project=project)

# Index route
@app.get('/')
@login_required
def index():
    search_query = request.args.get('search', '').strip()

    if search_query:
        projects = Project.query.filter(Project.name.ilike(f'%{search_query}%')).all()
    else:
        projects = Project.query.all()

    # Fetch news from a free movie news API
    import requests
    NEWS_API_KEY = os.getenv('NEWS_API_KEY')  # Use your API key
    news_url = f'https://newsapi.org/v2/everything?q=movies&apiKey={NEWS_API_KEY}'
    news = []
    try:
        response = requests.get(news_url)
        if response.status_code == 200:
            news = response.json().get('articles', [])
    except Exception as e:
        print(f"Error fetching news: {e}")

    return render_template('index.html', projects=projects, news=news)

# News route
@app.get('/news')
@login_required
def news():
    search_query = request.args.get('search', '').strip()

    # Fetch news from a free movie news API
    import requests
    NEWS_API_KEY = os.getenv('NEWS_API_KEY')  # Use your API key
    base_url = "https://newsapi.org/v2/everything"
    query = f"movies {search_query}" if search_query else "movies"
    params = {"q": query, "apiKey": NEWS_API_KEY}
    news = []

    try:
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            news = response.json().get('articles', [])
    except Exception as e:
        print(f"Error fetching news: {e}")

    return render_template('news.html', news=news)

# Registration page
@app.get('/register_page_user')
def register_page():
    return render_template('register.html')

# Registration logic
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
    return redirect(url_for('login_page'))

# Login page
@app.get('/login')
def login_page():
    return render_template('login.html')

# Login logic
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

# Logout route
@app.get('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login_page'))

# Profile route
@app.get('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Update profile picture
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
    
# Update profile information
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

# app.py


@app.route('/follow_user/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get_or_404(user_id)
    
    if user_to_follow == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('user_profile', user_id=user_id))
    
    if current_user.is_following(user_to_follow):
        flash('You are already following this user.', 'info')
    else:
        current_user.follow(user_to_follow)
        flash(f'You are now following {user_to_follow.username or user_to_follow.studio_name}.', 'success')
    
    return redirect(url_for('user_profile', user_id=user_id))


@app.route('/unfollow_user/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    user_to_unfollow = User.query.get_or_404(user_id)
    
    if user_to_unfollow == current_user:
        flash('You cannot unfollow yourself!', 'danger')
        return redirect(url_for('user_profile', user_id=user_id))
    
    if current_user.is_following(user_to_unfollow):
        current_user.unfollow(user_to_unfollow)
        flash(f'You have unfollowed {user_to_unfollow.username or user_to_unfollow.studio_name}.', 'success')
    else:
        flash('You are not following this user.', 'info')
    
    return redirect(url_for('user_profile', user_id=user_id))


# Follow a project
@app.route('/follow_project/<int:project_id>', methods=['POST'])
@login_required
def follow_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project in current_user.followed_projects:
        flash('You are already following this project.', 'info')
    else:
        current_user.followed_projects.append(project)
        db.session.commit()
        flash(f'You are now following the project "{project.name}".', 'success')
    return redirect(request.referrer or url_for('index'))

# Unfollow a project
@app.route('/unfollow_project/<int:project_id>', methods=['POST'])
@login_required
def unfollow_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project in current_user.followed_projects:
        current_user.followed_projects.remove(project)
        db.session.commit()
        flash(f'You have unfollowed the project "{project.name}".', 'success')
    else:
        flash('You are not following this project.', 'info')
    return redirect(request.referrer or url_for('index'))

# SocketIO event handlers for chat


@socketio.on('join')
def handle_join(data):
    project_id = data['project_id']
    room = f'project_{project_id}'
    join_room(room)
    emit('status', {
        'msg': f'{current_user.username or current_user.studio_name} has entered the room.'
    }, room=room)

@socketio.on('message')
def handle_message(data):
    content = data['message']
    project_id = data['project_id']
    room = f'project_{project_id}'

    # Save message to the database
    message = Message(content=content, user_id=current_user.id, project_id=project_id)
    db.session.add(message)
    db.session.commit()

    # Construct profile URL and picture URL
    profile_url = url_for('user_profile', user_id=current_user.id, _external=True)
    if current_user.profile_picture:
        profile_picture_url = url_for('static', filename='profile_pics/' + current_user.profile_picture, _external=True)
    else:
        profile_picture_url = url_for('static', filename='profile_pics/default_profile.png', _external=True)

    # Broadcast the message to the room
    emit('message', {
        'username': current_user.username or current_user.studio_name,
        'message': content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'profile_url': profile_url,
        'profile_picture_url': profile_picture_url
    }, room=room)

# Run the application with SocketIO
if __name__ == '__main__':
    socketio.run(app, debug=True)