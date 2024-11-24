import flask_login
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Table, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from flask_login import UserMixin

db = SQLAlchemy()

# Association table for the many-to-many relationship
user_roles = Table(
    'user_roles',
    db.Model.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(DateTime, server_default=db.func.now())
    studio_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship back to the studio
    studio = db.relationship('User', back_populates='projects')

    def __repr__(self):
        return f'<Project {self.name}>'

class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=True)  # Optional for studios
    last_name = db.Column(db.String(50), nullable=True)   # Optional for studios
    username = db.Column(db.String(50), unique=True, nullable=True)  # Optional for studios
    password = db.Column(db.Text, nullable=False)
    studio_name = db.Column(db.String(100), unique=True, nullable=True)  # For studios only
    created_at = db.Column(DateTime, server_default=db.func.now())
    profile_picture = db.Column(db.String(100), default='default.jpg')

    # Relationships
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    projects = db.relationship('Project', back_populates='studio', cascade='all, delete-orphan')

    # Self-referential relationship for following
    following = db.relationship(
        'User',
        secondary='follows',
        primaryjoin='User.id == Follows.follower_id',
        secondaryjoin='User.id == Follows.followed_id',
        backref='followers'
    )

    def get_roles(self):
        return [role.name for role in self.roles][0]  # Assume one role per user

    def can_follow(self):
        return 'Movie Studio' not in self.get_roles()

    def __repr__(self):
        return f'<User {self.username or self.studio_name}>'

# Follow association table
class Follows(db.Model):
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(DateTime, server_default=db.func.now())


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    # Relationship with User through user_roles table
    users = db.relationship('User', secondary=user_roles, back_populates='roles')

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f'<Role {self.name}>'
