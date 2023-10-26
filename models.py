from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import validates

db = SQLAlchemy()
#classes tables 


#uses class table

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_token = db.Column(db.String(64), unique=True)

#     # relationships with other tables
#     channels = db.relationship('Channel', backref='user', lazy=True)
#     messages = db.relationship('Message', backref='user', lazy=True)

#     # Relationship with ReportedUser
#     # Using the `ReportedUser.reporting_user_id` foreign key
#     reported_users = db.relationship('ReportedUser', backref='reporting_user', foreign_keys='ReportedUser.reporting_user_id', lazy=True)

#     # Relationship with ReportedMessage
#     # Using the `ReportedMessage.user_id` foreign key
#     reported_messages = db.relationship('ReportedMessage', backref='reporting_user', primaryjoin='User.id == ReportedMessage.user_id', lazy=True)

#      #email and password validations 
#     @validates('email')
#     def validate_email(self, key, email):
#         if '@' not in email:
#             raise ValueError('Invalid email format. Must contain "@"')
#         return email
    
#     @validates('password')
#     def validate_password(self, key, password):
#         if len(password) < 6:
#             raise ValueError("Password must be at least 6 characters long.")
#         return password

# #channels table 
# class Channel(db.Model):
#     __tablename__ = 'channels'
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(255), nullable=False)
#     description = db.Column(db.String(255), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     messages = db.relationship('Message', backref='channel', lazy=True)
#     group_messages = db.relationship('GroupMessage', backref='channel', lazy=True)

# #messsage table 
# class Message(db.Model):
#     __tablename__ = 'messages'
#     id = db.Column(db.Integer, primary_key=True)
#     message = db.Column(db.Text, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#     channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'))
#     message_date = db.Column(db.DateTime, default=datetime.utcnow)
#     parent_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
#     reported_messages = db.relationship('ReportedMessage', backref='message', foreign_keys='ReportedMessage.message_id', lazy=True)

# #groups_messages 
# class GroupMessage(db.Model):
#     __tablename__ = 'group_messages'
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     joined_at = db.Column(db.DateTime, default=datetime.utcnow)

# #reported_users table
# class ReportedUser(db.Model):
#     __tablename__ = 'reported_users'
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     reporting_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
#     report_date = db.Column(db.DateTime, nullable=False)
#     is_banned = db.Column(db.Boolean, nullable=False)
    
# #reported_messages table 
# class ReportedMessage(db.Model):
#     __tablename__ = 'reported_messages'
#     id = db.Column(db.Integer, primary_key=True)
#     reporting_user_id =db. Column(db.Integer,db.ForeignKey('users.id'))
#     user_id = db.Column(db.Integer,db.ForeignKey('users.id'))
#     message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
#     report_date = db.Column(db.DateTime, nullable=False)
#     is_banned = db.Column(db.Boolean, nullable=False)
#     __table_args__ = (db.ForeignKeyConstraint([reporting_user_id], ['users.id']),)
    
    
# #inivitations table 
# class Invitation(db.Model):
#     __tablename__ = 'invitations'
#     id = db.Column(db.Integer, primary_key=True, nullable=False)
#     sender_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     receiver_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
#     invitation_date = db.Column(db.Date, nullable=False)

