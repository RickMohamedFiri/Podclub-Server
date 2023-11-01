# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import validates
from sqlalchemy.orm import relationship
# from .base import Base  # Import your Base model

db = SQLAlchemy()
#classes tables 


#uses class table

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_token = db.Column(db.String(64), unique=True)
    role = db.Column(db.String(20))

    def __init__(self,user_name, email, password, verification_token, role):
        self.user_name = user_name
        self.email = email
        self.password = password 
        self.verification_token = verification_token
        self.role = role

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"

    # relationships with other tables
    channels = db.relationship('Channel', backref='user', lazy=True)
    messages = db.relationship('Message', backref='user', lazy=True)

    # Relationship with ReportedUser
    # Using the `ReportedUser.reporting_user_id` foreign key
    reported_users = db.relationship('ReportedUser', backref='reporting_user', foreign_keys='ReportedUser.reporting_user_id', lazy=True)

    # Relationship with ReportedMessage
    # Using the `ReportedMessage.user_id` foreign key
    reported_messages = db.relationship('ReportedMessage', backref='reporting_user', primaryjoin='User.id == ReportedMessage.user_id', lazy=True)


    group_chat_messages = db.relationship('GroupChatMessage', back_populates='user', lazy=True)
    image_messages = relationship('ImageMessage', back_populates='user')


 # Add a new field to track the number of group channels created by the user.
    # group_channels_count = db.Column(db.Integer, default=0)


     #email and password validations 
    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email:
            raise ValueError('Invalid email format. Must contain "@"')
        return email
    
    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        return password

#channels table 
class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy=True)
    # group_messages = db.relationship('GroupMessage', backref='channel', lazy=True)
    # group_messages = db.relationship('GroupMessage', backref='channel', lazy=True,
    # primaryjoin="Channel.id == GroupMessage.channel_id")
    group_messages = db.relationship('GroupMessage', primaryjoin="Channel.id == GroupMessage.channel_id", back_populates='channel')


#messsage table 
class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'))
    message_date = db.Column(db.DateTime, default=datetime.utcnow)
    parent_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
    reported_messages = db.relationship('ReportedMessage', backref='message', foreign_keys='ReportedMessage.message_id', lazy=True)

#groups_messages 
class GroupMessage(db.Model):
    __tablename__ = 'group_messages'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    # channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    channel = db.relationship('Channel', primaryjoin="GroupMessage.channel_id == Channel.id", back_populates='group_messages')

#reported_users table
class ReportedUser(db.Model):
    __tablename__ = 'reported_users'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    reporting_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    report_date = db.Column(db.DateTime, nullable=False)
    is_banned = db.Column(db.Boolean, nullable=False)
    
#reported_messages table 
class ReportedMessage(db.Model):
    __tablename__ = 'reported_messages'
    id = db.Column(db.Integer, primary_key=True)
    reporting_user_id =db. Column(db.Integer,db.ForeignKey('users.id'))
    user_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'))
    report_date = db.Column(db.DateTime, nullable=False)
    is_banned = db.Column(db.Boolean, nullable=False)
    __table_args__ = (db.ForeignKeyConstraint([reporting_user_id], ['users.id']),)
    
    






class GroupChannel(db.Model):
    __tablename__ = 'group_channels'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    channel_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('GroupChatMessage', backref='group_channel', lazy=True)

# Define the GroupChatMessage model
class GroupChatMessage(db.Model):
    __tablename__ = 'group_chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('group_channels.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    message_date = db.Column(db.DateTime, default=datetime.utcnow)
    parent_message_id = db.Column(db.Integer, db.ForeignKey('group_chat_messages.id'))
    # reported_messages = db.relationship('ReportedMessage', backref='group_message', foreign_keys='ReportedMessage.message_id', lazy=True)
    reported_messages = db.relationship('ReportedMessage', backref='group_message_relationship',  foreign_keys='ReportedMessage.message_id', primaryjoin='GroupChatMessage.id == ReportedMessage.message_id', lazy=True)
    # Define the relationship between GroupChatMessage and User (author)
    user = db.relationship('User', back_populates='messages')
    # Define the relationship between GroupChatMessage and GroupChannel
    channel = db.relationship('GroupChannel', back_populates='messages')
    user = db.relationship('User', back_populates='group_chat_messages')
    content = db.Column(db.String(255))



#  image messages
class ImageMessage(db.Model):
    __tablename__ = 'image_messages'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('group_channels.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    message_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define the relationship between ImageMessage and User (author)
    user = db.relationship('User', back_populates='image_messages')
    # Define the relationship between ImageMessage and GroupChannel
    channel = db.relationship('GroupChannel', back_populates='image_messages')

# Add a relationship between GroupChannel and ImageMessage
GroupChannel.image_messages = db.relationship('ImageMessage', back_populates='channel')

#user reports table 
class UserReport(db.Model):
    __tablename__ = 'user_reports'
    id = db.Column(db.Integer, primary_key=True)
    reporting_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_content_id = db.Column(db.Integer, nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.String(50))  # Store the action taken by moderators

    def __init__(self, reporting_user_id, reported_user_id, reported_content_id, action_taken):
        self.reporting_user_id = reporting_user_id
        self.reported_user_id = reported_user_id
        self.reported_content_id = reported_content_id
        self.action_taken = action_taken
