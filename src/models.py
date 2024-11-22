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

class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    created_at = db.Column(DateTime, server_default=db.func.now())

    # Relationship with Role through user_roles table
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')

    def get_roles(self):
        return [role.name for role in self.roles][0]

    def __init__(self, first_name, last_name, username, password):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User {self.username}>'

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
