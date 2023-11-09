# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import validates
from sqlalchemy.orm import relationship
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import ForeignKey



db = SQLAlchemy()

def generate_unique_token():
    token = secrets.token_hex(16)
    return token

#uses class table
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))  # Add this line to define the user_name column
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime)
    verification_token = db.Column(db.String(64), unique=True)
    role = db.Column(db.String(50))
    # relationships with other tables
    channels = db.relationship('Channel', backref='user', lazy=True)
    messages = db.relationship('Messages', backref='user', lazy=True)
    reported_users = db.relationship('ReportedUser', backref='reporting_user', foreign_keys='ReportedUser.reporting_user_id', lazy=True)
    reported_messages = db.relationship('ReportedMessage', backref='reporting_user', primaryjoin='User.id == ReportedMessage.user_id', lazy=True)
    group_chat_messages = db.relationship('GroupChatMessage', back_populates='user', lazy=True)
    image_messages = relationship('ImageMessage', back_populates='user')
    # Add a new field to track the number of group channels created by the user.
    # group_channels_count = db.Column(db.Integer, default=0)

# Flask-Login UserMixin properties and methods
    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False
# Add a function to validate and hash passwords
def validate_and_hash_password(form, field):
    if len(field.data) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    return generate_password_hash(field.data, method='sha256')

# Add the email and password validation to the User model
@validates('email')
def validate_email(self, key, email):
    if '@' not in email:
        raise ValueError('Invalid email format. Must contain "@"')
    return email

@validates('password')
def validate_password(self, key, password):
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    return validate_and_hash_password(None, password)

#channels table 
class Channel(db.Model):
    __tablename__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Messages', backref='channel', lazy=True)
    group_messages = db.relationship('GroupMessage', backref='channel', lazy=True)

#messsage table 
class Messages(db.Model):
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
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

#reported_users table
class ReportedUser(db.Model):
    __tablename__ = 'reported_users'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    reporting_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=db.func.current_timestamp(), nullable=True)
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
    # Define the relationships
    reported_messages = db.relationship('ReportedMessage', backref='group_message_relationship',  foreign_keys='ReportedMessage.message_id', primaryjoin='GroupChatMessage.id == ReportedMessage.message_id', lazy=True)
    user = db.relationship('User', back_populates='messages')
    channel = db.relationship('GroupChannel', back_populates='messages')
    user = db.relationship('User', back_populates='group_chat_messages')
    content = db.Column(db.String(255))

# image messages table
class ImageMessage(db.Model):
    __tablename__ = 'image_messages'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('group_channels.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    message_date = db.Column(db.DateTime, default=datetime.utcnow)
    # Define the relationships
    user = db.relationship('User', back_populates='image_messages')
    channel = db.relationship('GroupChannel', back_populates='image_messages')
    GroupChannel.image_messages = db.relationship('ImageMessage', back_populates='channel')

# Define the Admin model with permissions
class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    can_ban_users = db.Column(db.Boolean, default=False)
    can_delete_channels = db.Column(db.Boolean, default=False)

# #user reports table 
# class UserReport(db.Model):
#     __tablename__ = 'user_reports'
#     id = db.Column(db.Integer, primary_key=True)
#     reporting_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     reported_content_id = db.Column(db.Integer, nullable=False)
#     report_date = db.Column(db.DateTime, default=datetime.utcnow)
#     action_taken = db.Column(db.String(50))  # Store the action taken by moderators

#     def __init__(self, reporting_user_id, reported_user_id, reported_content_id,action_taken):
#         self.reporting_user_id = reporting_user_id
#         self.reported_user_id = reported_user_id
#         self.reported_content_id = reported_content_id
#         self.action_taken = action_taken

# invitation table 
class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    sender_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    invitation_date = db.Column(db.Date, nullable=False)
    unique_token = db.Column(db.String(32), nullable=False)  # Adjust the data type and length as needed

    # Other model attributes...

    def __init__(self, sender_user_id, receiver_user_id, channel_id, unique_token, invitation_date):
        self.sender_user_id = sender_user_id
        self.receiver_user_id = receiver_user_id
        self.channel_id = channel_id
        self.unique_token = unique_token
        self.invitation_date = invitation_date





    