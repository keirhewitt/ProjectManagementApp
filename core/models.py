from core import db
from flask_login import UserMixin
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

now = datetime.now()


class Room(db.Model):
    __tablename__ = 'room'
    key = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    task = relationship("Task")

# Database table Task
class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), ForeignKey('room.key'))
    project = db.Column(db.String(100))
    job = db.Column(db.String(200))
    assignee = db.Column(db.String(40))
    progress = db.Column(db.String(200))
    description = db.Column(db.UnicodeText(), nullable=False)
    date = db.Column(db.String(30), default=now.strftime("%m/%d/%Y %H:%M"))

    def __repr__(self):
        return '<Task %r>' % self.id

# Database table User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)