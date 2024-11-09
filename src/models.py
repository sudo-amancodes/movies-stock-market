from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from flask_login import UserMixin


db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    username = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    profile_picture = Column(String(255),default='default.jpg')

    watchlist_teams = db.relationship('UserWatchlistTeams', backref='user', lazy=True)

    
    def get_id(self):
        return str(self.user_id)


class SoccerTeam(db.Model):
    __tablename__ = 'soccer_teams'
    team_id = Column(Integer, primary_key=True)
    team_name = Column(String(255), nullable=False)
    wins_draws_losses = Column(String(50))
    logo = Column(String(255))

    def __str__(self):
        return f"{self.team_id}, {self.team_name}, {self.wins_draws_losses}, {self.logo}"

class UserWatchlistTeams(db.Model):
    __tablename__ = 'user_watchlist_teams'
    user_id = Column(Integer, ForeignKey('users.user_id'), primary_key=True)
    team_id = Column(Integer, ForeignKey('soccer_teams.team_id'), primary_key=True)

    def __str__(self):
        return f"{self.user_id}, {self.team_id}"


