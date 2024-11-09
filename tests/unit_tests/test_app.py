import pytest, os
from app import app, db, User, SoccerTeam, UserWatchlistTeams
from flask import url_for
from werkzeug.security import generate_password_hash

import os
import pytest
from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' 
    app.config['WTF_CSRF_ENABLED'] = False  

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()



def create_user(username, password):
    user = User(
        first_name="Test",
        last_name="User",
        username=username,
        password=generate_password_hash(password, method='pbkdf2:sha256:600000')
    )
    db.session.add(user)
    db.session.commit()
    return user

def test_register(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b'Register' in response.data

    response = client.post('/register', data={
        'first_name': 'John',
        'last_name': 'Doe',
        'username': 'johndoe',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Registration successful. Please log in.' in response.data

    response = client.post('/register', data={
        'first_name': 'John',
        'last_name': 'Doe',
        'username': 'johndoe',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Username already exists.' in response.data

def test_login(client):
    create_user('johndoe', 'password123')
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data
    response = client.post('/login', data={
        'username': 'johndoe',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Login successful!' in response.data
    response = client.post('/login', data={
        'username': 'johndoe',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid username or password.' in response.data

def test_profile_page_access(client):
    user = create_user('johndoe', 'password123')

    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.user_id)

    response = client.get('/profile')
    assert response.status_code == 200
    assert b'Profile' in response.data

def test_add_to_watchlist(client):
    user = create_user('johndoe', 'password123')

    team = SoccerTeam(team_id=1, team_name="Test Team", wins_draws_losses="3-2-1", logo="test_logo.png")
    db.session.add(team)
    db.session.commit()

    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.user_id)

    response = client.post('/add_to_watchlist', json={'team_id': 1})
    assert response.status_code == 200
    assert b'Team added to watchlist successfully!' in response.data

    response = client.post('/add_to_watchlist', json={'team_id': 1})
    assert response.status_code == 200
    assert b'Team is already in your watchlist.' in response.data
