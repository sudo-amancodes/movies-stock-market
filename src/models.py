# src/models.py

import flask_login
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# Association table for user roles
user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

# Association table for users following projects
project_follows = db.Table(
    'project_follows',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('projects.id'), primary_key=True)
)

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    banner = db.Column(db.String(255), nullable=True)
    created_at = db.Column(DateTime, server_default=db.func.now())
    studio_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationship back to the studio
    studio = db.relationship('User', back_populates='projects')

    # Followers relationship
    followers = db.relationship('User', secondary=project_follows, back_populates='followed_projects')

    # Messages relationship
    messages = db.relationship('Message', back_populates='project', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Project {self.name}>'

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password = db.Column(db.Text, nullable=False)
    studio_name = db.Column(db.String(100), unique=True, nullable=True)
    created_at = db.Column(DateTime, server_default=db.func.now())
    profile_picture = db.Column(db.String(100), default='default.jpg')

    # Relationships
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    projects = db.relationship('Project', back_populates='studio', cascade='all, delete-orphan')
    messages = db.relationship('Message', back_populates='author', cascade='all, delete-orphan')

    # Association object relationships for following
    following_associations = db.relationship(
        'Follows',
        foreign_keys='Follows.follower_id',
        back_populates='follower',
        cascade='all, delete-orphan'
    )

    followers_associations = db.relationship(
        'Follows',
        foreign_keys='Follows.followed_id',
        back_populates='followed',
        cascade='all, delete-orphan'
    )

    # Helper properties to get lists of User objects
    @property
    def following_users(self):
        return [association.followed for association in self.following_associations]

    @property
    def followers_users(self):
        return [association.follower for association in self.followers_associations]

    # Followed projects
    followed_projects = db.relationship('Project', secondary=project_follows, back_populates='followers')

    def get_roles(self):
        return [role.name for role in self.roles][0]  # Assumes one role per user

    def can_follow(self):
        return 'Movie Studio' not in self.get_roles()

    def __repr__(self):
        return f'<User {self.username or self.studio_name}>'
    
    def follow(self, user):
        if not self.is_following(user):
            follow = Follows(follower_id=self.id, followed_id=user.id)
            db.session.add(follow)
            db.session.commit()

    def unfollow(self, user):
        follow = Follows.query.filter_by(follower_id=self.id, followed_id=user.id).first()
        if follow:
            db.session.delete(follow)
            db.session.commit()

    def is_following(self, user):
        return Follows.query.filter_by(follower_id=self.id, followed_id=user.id).first() is not None

    def __repr__(self):
        return f'<User {self.username or self.studio_name}>'

class Follows(db.Model):
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Unique constraint to prevent duplicate follows
    __table_args__ = (
        db.UniqueConstraint('follower_id', 'followed_id', name='unique_follows'),
    )

    # Relationships to User
    follower = db.relationship('User', foreign_keys=[follower_id], back_populates='following_associations')
    followed = db.relationship('User', foreign_keys=[followed_id], back_populates='followers_associations')

class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(DateTime, server_default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)

    # Relationships
    author = db.relationship('User', back_populates='messages')
    project = db.relationship('Project', back_populates='messages')

    def to_dict(self):
        return {
            'username': self.author.username or self.author.studio_name,
            'content': self.content,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }

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
