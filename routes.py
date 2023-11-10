import secrets
from flask import jsonify, request,abort,redirect, render_template, url_for
from flask_jwt_extended import JWTManager
from app import app, db, mail 
from flask_cors import CORS
import secrets
from datetime import datetime
from datetime import timedelta
from flask_jwt_extended import JWTManager,jwt_required, get_jwt_identity
from marshmallow import ValidationError
from validation import DataValidationSchema
from passlib.hash import sha256_crypt
from models import User, Channel, Messages, GroupMessage, ReportedUser, ReportedMessage, GroupChannel, GroupChatMessage, ImageMessage, Invitation
from datetime import datetime
from flask_mail import Message, Mail
from flask_jwt_extended import create_access_token, jwt_required
from flask_login import login_user, login_required
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

mail = Mail(app)
CORS(app)

@app.route('/')
def message():
    return 'Welcome to the channels API'


## Authentication
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Generate an access token
        access_token = create_access_token(identity=user.id)

        # Log in the user
        login_user(user)

        # Include the user_id, user_name, and access token in the response
        return jsonify({
            'user_id': user.id,
            'user_name': user.user_name,
            'access_token': access_token,
            'message': 'Login successful'
        })

    return jsonify({'message': 'Invalid email or password'}, 401)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Extract user registration data from the JSON data
    user_name = data.get('user_name')
    email = data.get('email')
    password = data.get('password')

    # Check if the email is not already in use
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already in use'}, 409)

    # Create a new user with the hashed password
    new_user = User(
        user_name=user_name,
        email=email,
        password=generate_password_hash(password, method='pbkdf2:sha256')
    )
    db.session.add(new_user)
    db.session.commit()

    # Log in the newly registered user
    login_user(new_user)

    # Return user information including the user id
    response_data = {
        'user_id': new_user.id,
        'user_name': new_user.user_name,
        'email': new_user.email,
        'message': 'User registered and logged in'
    }

    # Generate and return an access token for the newly registered user
    access_token = create_access_token(identity=str(new_user.id))
    response_data['access_token'] = access_token

    return jsonify(response_data)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()  # Log out the user
    return jsonify({'message': 'Logged out successfully'})

@app.route('/protected_route', methods=['GET'])
@login_required
def protected_route():
    # This route is only accessible to authenticated users
    return jsonify({'message': 'This is a protected route'})

# Get all Users endpoint
@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'user_name': user.user_name, 'email': user.email} for user in users]
    return jsonify(user_list)

# update user 
@app.route('/update_user', methods=['PUT'])
@jwt_required()
def update_user():
    # Get the user's ID from the JWT token
    current_user_id = get_jwt_identity()

    # Get the user object
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'message': 'User not found'}, 404)

    data = request.get_json()
    # For example, you might allow users to update their user_name or email
    user_name = data.get('user_name')
    email = data.get('email')

    if user_name:
        user.user_name = user_name

    if email:
        # Check if the new email is not already in use
        existing_user = User.query.filter_by(email=email).first()
        if existing_user and existing_user.id != current_user_id:
            return jsonify({'message': 'Email already in use'}, 409)
        user.email = email

    # Commit the changes to the database
    db.session.commit()

    return jsonify({'message': 'User information updated successfully'})


# # Create Channel endpoint
# @app.route('/channels', methods=['POST'])
# def create_channel():
#     new_channel = Channel(name=request.json['name'], description=request.json['description'], user_id=request.json['user_id'])
#     db.session.add(new_channel)
#     db.session.commit()
#     return jsonify({'message': 'Channel created successfully'})
# Create Channel endpoint
@app.route('/channels', methods=['POST'])
def create_channel():
    new_channel = Channel(
        name=request.get_json()['name'],
        description=request.get_json()['description'],
        user_id=request.get_json()['user_id']
    )
    db.session.add(new_channel)
    db.session.commit()
    return jsonify({'message': 'Channel created successfully'})

# Get all Channels endpoint
@app.route('/channels', methods=['GET'])
def get_all_channels():
    channels = Channel.query.all()
    channel_list = [{'id': channel.id, 'name': channel.name, 'description': channel.description} for channel in channels]
    return jsonify(channel_list)

# Update Channel endpoint
@app.route('/channels/<int:channel_id>', methods=['PATCH'])
def update_channel(channel_id):
    channel = Channel.query.get(channel_id)
    if channel:
        channel.name = request.json.get('name', channel.name)
        channel.description = request.json.get('description', channel.description)
        channel.user_id = request.json.get('user_id', channel.user_id)
        db.session.commit()
        return jsonify({'message': 'Channel updated successfully'})
    else:
        return jsonify({'message': 'Channel not found'}, 404)

# Message endpoint
@app.route('/messages', methods=['POST'])
def create_message():
    new_message = Messages(message=request.json['message'], user_id=request.json['user_id'], channel_id=request.json['channel_id'])
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'message': 'Message created successfully'})

#  All Messages endpoint
@app.route('/messages', methods=['GET'])
def get_all_messages():
    messages = Messages.query.all()
    message_list = [{'id': message.id, 'message': message.message, 'user_id': message.user_id, 'channel_id': message.channel_id} for message in messages]
    return jsonify(message_list)

# Update Message endpoint
@app.route('/messages/<int:message_id>', methods=['PATCH'])
def update_message(message_id):
    message = Messages.query.get(message_id)
    if message:
        message.message = request.json.get('message', message.message)
        message.user_id = request.json.get('user_id', message.user_id)
        message.channel_id = request.json.get('channel_id', message.channel_id)
        db.session.commit()
        return jsonify({'message': 'Message updated successfully'})
    else:
        return jsonify({'message': 'Message not found'}, 404)

# Delete Message endpoint
@app.route('/messages/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    message = Messages.query.get(message_id)
    if message:
        db.session.delete(message)
        db.session.commit()
        return jsonify({'message': 'Message deleted successfully'})
    else:
        return jsonify({'message': 'Message not found'}, 404)


# Create GroupMessage endpoint
@app.route('/group_messages', methods=['POST'])
def create_group_message():
    new_group_message = GroupMessage(channel_id=request.json['channel_id'], user_id=request.json['user_id'])
    db.session.add(new_group_message)
    db.session.commit()
    return jsonify({'message': 'Group message created successfully'})

# Get all GroupMessages endpoint
@app.route('/group_messages', methods=['GET'])
def get_all_group_messages():
    group_messages = GroupMessage.query.all()
    group_message_list = [{'id': group_message.id, 'channel_id': group_message.channel_id, 'user_id': group_message.user_id} for group_message in group_messages]
    return jsonify(group_message_list)

# Update GroupMessage endpoint
@app.route('/group_messages/<int:group_message_id>', methods=['PATCH'])
def update_group_message(group_message_id):
    group_message = GroupMessage.query.get(group_message_id)
    if group_message:
        group_message.channel_id = request.json.get('channel_id', group_message.channel_id)
        group_message.user_id = request.json.get('user_id', group_message.user_id)
        db.session.commit()
        return jsonify({'message': 'Group message updated successfully'})
    else:
        return jsonify({'message': 'Group message not found'}, 404)

# Delete GroupMessage endpoint
@app.route('/group_messages/<int:group_message_id>', methods=['DELETE'])
def delete_group_message(group_message_id):
    group_message = GroupMessage.query.get(group_message_id)
    if group_message:
        db.session.delete(group_message)
        db.session.commit()
        return jsonify({'message': 'Group message deleted successfully'})
    else:
        return jsonify({'message': 'Group message not found'}, 404)


# ReportedUser endpoint
@app.route('/reported_users', methods=['POST'])
def create_reported_user():
    new_reported_user = ReportedUser(
        reporting_user_id=request.json['reporting_user_id'],
        reported_user_id=request.json['reported_user_id'],
        message_id=request.json['message_id'],
        is_banned=request.json['is_banned'],
        report_date=None  # Set report_date to None
    )
    db.session.add(new_reported_user)
    db.session.commit()
    return jsonify({'message': 'Reported user created successfully'})

# All ReportedUsers endpoint
@app.route('/reported_users', methods=['GET'])
def get_all_reported_users():
    reported_users = ReportedUser.query.all()
    reported_user_list = [{'id': reported_user.id, 'reporting_user_id': reported_user.reporting_user_id, 'reported_user_id': reported_user.reported_user_id, 'message_id': reported_user.message_id, 'is_banned': reported_user.is_banned} for reported_user in reported_users]
    return jsonify(reported_user_list)

# Update ReportedUser endpoint
@app.route('/reported_users/<int:reported_user_id>', methods=['PATCH'])
def update_reported_user(reported_user_id):
    reported_user = ReportedUser.query.get(reported_user_id)
    if reported_user:
        reported_user.reporting_user_id = request.json.get('reporting_user_id', reported_user.reporting_user_id)
        reported_user.reported_user_id = request.json.get('reported_user_id', reported_user.reported_user_id)
        reported_user.message_id = request.json.get('message_id', reported_user.message_id)
        reported_user.is_banned = request.json.get('is_banned', reported_user.is_banned)
        db.session.commit()
        return jsonify({'message': 'Reported user updated successfully'})
    else:
        return jsonify({'message': 'Reported user not found'}, 404)

# Delete ReportedUser endpoint              
@app.route('/reported_users/<int:reported_user_id>', methods=['DELETE'])
def delete_reported_user(reported_user_id):
    reported_user = ReportedUser.query.get(reported_user_id)
    if reported_user:
        db.session.delete(reported_user)
        db.session.commit()
        return jsonify({'message': 'Reported user deleted successfully'})
    else:
        return jsonify({'message': 'Reported user not found'}, 404)


# Get all ReportedUsers endpoint (only accessible to admins)
@app.route('/admin/reported_users', methods=['GET'])
def get_all_reported_users_admin():
    # Check if the current user is an admin with permission to view reported users
    current_user = User.query.get(1) 
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 401

    reported_users = ReportedUser.query.all()
    reported_user_list = []

    for reported_user in reported_users:
        user = User.query.get(reported_user.user_id)
        reported_user_list.append({
            'id': reported_user.id,
            'user_id': reported_user.user_id,
            'username': user.user_name,
            'is_banned': reported_user.is_banned
        })

    return jsonify({'reported_users': reported_user_list})

# Ban Reported User endpoint (only accessible to admins)
@app.route('/admin/ban_user/<int:user_id>', methods=['POST'])
def ban_user(user_id):
    # Check if the current user is an admin with permission to ban users
    current_user = User.query.get(1)  
    if not current_user or not current_user.is_admin or not current_user.admin_permissions.can_ban_users:
        return jsonify({'error': 'Unauthorized'}), 401

    reported_user = ReportedUser.query.filter_by(user_id=user_id).first()
    if reported_user:
        reported_user.is_banned = True
        db.session.commit()
        return jsonify({'message': 'User banned successfully'})
    else:
        return jsonify({'message': 'Reported user not found'}, 404)

# Unban Reported User endpoint (only accessible to admins)
@app.route('/admin/unban_user/<int:user_id>', methods=['POST'])
def unban_user(user_id):
    # Check if the current user is an admin with permission to unban users
    current_user = User.query.get(1)  
    if not current_user or not current_user.is_admin or not current_user.admin_permissions.can_ban_users:
        return jsonify({'error': 'Unauthorized'}), 401

    reported_user = ReportedUser.query.filter_by(user_id=user_id).first()
    if reported_user:
        reported_user.is_banned = False
        db.session.commit()
        return jsonify({'message': 'User unbanned successfully'})
    else:
        return jsonify({'message': 'Reported user not found'}, 404)
# Create the group channel endpoint
@app.route('/group_channels', methods=['POST'])
def create_group_channel():
    # Extract user input from the request
    user_id = request.json.get('user_id')
    channel_name = request.json.get('channel_name')
    description = request.json.get('description')

    # Create the group channel in the database
    new_channel = GroupChannel(user_id=user_id, channel_name=channel_name, description=description)
    db.session.add(new_channel)
    db.session.commit()

    return jsonify({'message': 'Group channel created successfully'})

# GET endpoint to fetch group channels
@app.route('/group_channels', methods=['GET'])
def get_group_channels():
    # Retrieve group channels from the database (you need to implement this)
    group_channels = GroupChannel.query.all()  # You need to define the GroupChannel model and query accordingly

    # Create a list to store group channel data
    group_channel_list = []

    # Convert group channels to a list of dictionaries
    for group_channel in group_channels:
        group_channel_data = {
            'user_id': group_channel.user_id,
            'channel_name': group_channel.channel_name,
            'description': group_channel.description,
        }
        group_channel_list.append(group_channel_data)

    # Return the list of group channels as a JSON response
    return jsonify(group_channel_list)

@app.route('/group_channels/<int:channel_id>', methods=['GET'])
def get_group_channel_by_id(channel_id):
    # Retrieve the group channel from the database based on the provided ID
    group_channel = GroupChannel.query.get(channel_id)  # You need to define the GroupChannel model

    if not group_channel:
        return jsonify({'message': 'Group channel not found'}, 404)

    # Create a dictionary to store the group channel data
    group_channel_data = {
        'user_id': group_channel.user_id,
        'channel_name': group_channel.channel_name,
        'description': group_channel.description,
    }

    # Return the group channel data as a JSON response
    return jsonify(group_channel_data)


# Update Group Channel Description endpoin
@app.route('/group_channels/<int:channel_id>', methods=['PATCH'])
def update_group_channel_description(channel_id):
    # Find the group channel by its ID
    channel = GroupChannel.query.get(channel_id)
    if channel:
        # Update the channel description
        new_description = request.json.get('new_description')
        channel.description = new_description
        db.session.commit()
        return jsonify({'message': 'Group channel description updated successfully'})
    else:
        return jsonify({'message': 'Group channel not found'}, 404)

# Create the route to delete a group channel 
@app.route('/group_channels/<int:channel_id>', methods=['DELETE'])
def delete_group_channel(channel_id):
    # Find the group channel by its ID
    channel = GroupChannel.query.get(channel_id)

    if not channel:
        return jsonify({'message': 'Group channel not found'}, 404)

    # Delete the channel
    db.session.delete(channel)
    db.session.commit()

    return jsonify({'message': 'Group channel deleted successfully'})

# Create the group chat message endpoint
@app.route('/group_chat_messages', methods=['POST'])
def add_message_to_group_chat():
    # Extract message content and user ID from the request
    user_id = request.json.get('user_id')
    message_content = request.json.get('message_content')
    channel_id = request.json.get('channel_id')  # Add channel ID to the request

    # Create and store the message in the database
    new_message = GroupChatMessage(channel_id=channel_id, user_id=user_id, content=message_content)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message added to the group chat'})

# GET endpoint to fetch group chat messages
@app.route('/group_chat_messages', methods=['GET'])
def get_group_chat_messages():
    # Retrieve group chat messages from the database (you need to implement this)
    group_chat_messages = GroupChatMessage.query.all()  # You need to define the GroupChatMessage model and query accordingly

    # Create a list to store group chat message data
    group_chat_message_list = []

    # Convert group chat messages to a list of dictionaries
    for group_chat_message in group_chat_messages:
        group_chat_message_data = {
            'channel_id': group_chat_message.channel_id,
            'user_id': group_chat_message.user_id,
            'message_content': group_chat_message.content,
        }
        group_chat_message_list.append(group_chat_message_data)

    # Return the list of group chat messages as a JSON response
    return jsonify(group_chat_message_list)

# Reply to Message in group chat enpoint
@app.route('/group_chat_messages/<int:message_id>/reply', methods=['POST'])
def reply_to_message(message_id):
    # Extract user ID and reply content from the request
    user_id = request.json.get('user_id')
    reply_content = request.json.get('reply_content')
    channel_id = request.json.get('channel_id')  # Add channel ID to the request

    # Create and store the reply in the database
    new_reply = GroupChatMessage(channel_id=channel_id, user_id=user_id, content=reply_content, parent_message_id=message_id)
    db.session.add(new_reply)
    db.session.commit()

    return jsonify({'message': 'Reply added to the message'})

# Update group chat message endpoint
@app.route('/group_chat_messages/<int:message_id>', methods=['PATCH'])
def update_group_chat_message(message_id):
    # Extract user ID and updated message content from the request
    user_id = request.json.get('user_id')
    updated_message_content = request.json.get('updated_message_content')

    # Find the message to update
    message = GroupChatMessage.query.filter_by(id=message_id, user_id=user_id).first()

    if message:
        message.content = updated_message_content
        db.session.commit()
        return jsonify({'message': 'Message updated successfully'})
    else:
        return jsonify({'message': 'Message not found or unauthorized to update'}, 404)

# Delete group chat message endpoint
@app.route('/group_chat_messages/<int:message_id>', methods=['DELETE'])
def delete_group_chat_message(message_id):
    # Extract user ID from the request
    user_id = request.json.get('user_id')

    # Find the message to delete
    message = GroupChatMessage.query.filter_by(id=message_id, user_id=user_id).first()

    if message:
        db.session.delete(message)
        db.session.commit()
        return jsonify({'message': 'Message deleted successfully'})
    else:
        return jsonify({'message': 'Message not found or unauthorized to delete'}, 404)
    


# image message endpoint
@app.route('/image_messages', methods=['POST'])
def create_image_message():
    # Extract data from the request
    data = request.get_json()
    channel_id = data.get('channel_id')
    user_id = data.get('user_id')
    image_url = data.get('image_url')
    message_date_str = data.get('message_date')  # Get the date string

    # Convert the date string to a datetime object
    message_date = datetime.strptime(message_date_str, '%Y-%m-%d %H:%M:%S.%f')

    # Create an ImageMessage object
    new_image_message = ImageMessage(
        channel_id=channel_id,
        user_id=user_id,
        image_url=image_url,
        message_date=message_date  # Use the datetime object
    )

    # Add the image message to the database
    db.session.add(new_image_message)
    db.session.commit()

    # Return a JSON response
    return jsonify({'message': 'Image message created successfully'})


# GET endpoint to fetch image messages
@app.route('/image_messages', methods=['GET'])
def get_image_messages():
    # Retrieve image messages from the database (you need to implement this)
    image_messages = ImageMessage.query.all()  # You need to define the ImageMessage model and query accordingly

    # Create a list to store image message data
    image_message_list = []

    # Convert image messages to a list of dictionaries
    for image_message in image_messages:
        image_message_data = {
            'channel_id': image_message.channel_id,
            'user_id': image_message.user_id,
            'image_url': image_message.image_url,
            'message_date': image_message.message_date.strftime('%Y-%m-%d %H:%M:%S.%f')
        }
        image_message_list.append(image_message_data)

    # Return the list of image messages as a JSON response
    return jsonify(image_message_list)


# @app.route('/invitations/<int:channel_id>/accept', methods=['GET'])
# def accept_invitation(channel_id):
#     # Extract the token from the URL
#     token = request.args.get('token')

#     # Validate the token
#     if validate_invitation_token(channel_id, token):
#         user_id = get_current_user_id()
        
#         if user_id:
#             # Add the user to the group channel (you need to implement this)
#             # For example, you can create a new record in your database
#             # to associate the user with the group channel.
            
#             # Ensure that the user is not already a member of the channel
#             if not is_user_member_of_channel(user_id, channel_id):
#                 add_user_to_group_channel(user_id, channel_id)
#                 return jsonify({'message': 'Invitation accepted successfully'})
#             else:
#                 return jsonify({'message': 'User is already a member of the channel'}, 400)
#         else:
#             return jsonify({'message': 'Invalid user or not logged in'}, 400)
#     else:
#         return jsonify({'message': 'Invalid or expired invitation link'}, 400)
# def validate_invitation_token(channel_id, token):
#     # Retrieve the invitation record from the database based on the provided token
#     invitation = Invitation.query.filter_by(group_channel_id=channel_id, token=token).first()

#     if invitation:
#         # Check if the token is associated with the specified channel
#         if invitation.group_channel_id == channel_id:
#             # Check if the token hasn't expired
#             expiration_time = invitation.created_at + timedelta(days=1)  # Adjust the expiration time as needed
#             if datetime.utcnow() <= expiration_time:
#                 return True  # Token is valid
#             else:
#                 return False  # Token has expired
#         else:
#             return False  # Token is not associated with the specified channel
#     else:
#         return False  # Token doesn't exist in the database
    

# def get_current_user_id():
#     # function to get the ID of the currently logged-in user
#     # You can use Flask-Login's current_user to get the user object and then access the ID
#     if current_user.is_authenticated:
#         return current_user.id
#     else:
#         return None

# def add_user_to_group_channel(user_id, channel_id):
#     # Implement the logic to add the user to the group channel
#     user = User.query.get(user_id)
#     channel = GroupChannel.query.get(channel_id)
    
#     if user and channel:
#         # Check if the user is not already a member of the channel
#         if user not in channel.members:
#             channel.members.append(user)
#             db.session.commit()

# def is_user_member_of_channel(user_id, channel_id):
#     # Check if the user with the given user_id is a member of the channel with the given channel_id
#     user = User.query.get(user_id)
#     channel = GroupChannel.query.get(channel_id)

#     if user and channel:
#         # Assuming there's a many-to-many relationship between users and group channels
#         return channel in user.group_channels

#     return False


##reported messages endpoints 



# Get Reported Messages
@app.route('/reported_messages', methods=['GET'])
def get_reported_messages():
    reported_messages = ReportedMessage.query.all()
    reported_messages_list = []
    for reported_message in reported_messages:
        reported_messages_list.append({
            'id': reported_message.id,
            'reporting_user_id': reported_message.reporting_user_id,
            'user_id': reported_message.user_id,
            'message_id': reported_message.message_id,
            'report_date': reported_message.report_date.strftime('%Y-%m-%d %H:%M:%S'),
            'is_banned': reported_message.is_banned
        })
    return jsonify(reported_messages_list)

# Create a New Reported Message
@app.route('/reported_messages', methods=['POST'])
def create_reported_message():
    data = request.get_json()
    report_date_str = data['report_date']  # Assuming report_date is provided as a string
    report_date = datetime.strptime(report_date_str, '%Y-%m-%d %H:%M:%S')  # Convert the string to datetime

    new_reported_message = ReportedMessage(
        reporting_user_id=data['reporting_user_id'],
        user_id=data['user_id'],
        message_id=data['message_id'],
        report_date=report_date,  # Use the datetime object here
        is_banned=data['is_banned']
    )

    db.session.add(new_reported_message)
    db.session.commit()
    return jsonify({'message': 'Reported message created successfully!'})

# Delete a Reported Message
@app.route('/reported_messages/<int:id>', methods=['DELETE'])
def delete_reported_message(id):
    reported_message = ReportedMessage.query.get(id)
    if reported_message:
        db.session.delete(reported_message)
        db.session.commit()
        return jsonify({'message': 'Reported message deleted successfully'})
    else:
        return jsonify({'message': 'Reported message not found'})



@app.route('/send_invitation_email', methods=['POST'])
def send_invitation_email():
    if request.method == 'POST':
        recipient_email = request.json.get('recipient_email')
        channel_id = request.json.get('channel_id')
        
        # Generate a unique token for this invitation
        unique_token = secrets.token_urlsafe(16)  # Generate a 32-character URL-safe token
        
        # Create the invitation link with the unique token
        invitation_link = f'http://127.0.0.1:5000/invitations/{channel_id}/accept?token={unique_token}'

        # Create an email message
        subject = 'You are invited to join our group channel'
        body = f'Click the following link to join our group channel: {invitation_link}'
        sender = 'yusramoham99@gmail.com'  # Replace with your email address
        recipients = [recipient_email]

        msg = Message(subject=subject, sender=sender, recipients=recipients)
        msg.body = body

        try:
            mail.send(msg)
            return jsonify({'message': 'Invitation email sent successfully'})
        except Exception as e:
            return jsonify({'message': f'Failed to send the invitation email: {str(e)}'}, 500)

    return jsonify({'message': 'Invalid request'}, 400)   

invitations = {
    1: {'token': 'your_unique_token_here', 'group_channel': 'Group A'},
    2: {'token': 'another_unique_token', 'group_channel': 'Group B'},
}
def verify_token(channel_id, token):
    # Verify the token against your data structure (in a real app, check against a database)
    if channel_id in invitations and invitations[channel_id]['token'] == token:
        return True
    return False

@app.route('/invitations/<int:channel_id>/accept', methods=['GET'])
def accept_invitation(channel_id):
    # Extract the token from the URL
    token = request.args.get('token')
    # Print the channel_id and token for debugging
    print(f"Received channel_id: {channel_id}")
    print(f"Received token: {token}")

    # Verify the token
    if verify_token(channel_id, token):
        # Add the user to the group channel (simulate by updating the data structure)
        user = 'New User'
        invitations[channel_id]['members'] = invitations.get(channel_id, {}).get('members', []) + [user]

        # Redirect to a confirmation page (or you can render an HTML page)
        return jsonify({'message': 'Invitation accepted successfully'})

    # Invalid token, show an error or redirect to an error page
    return jsonify({'message': 'Invalid or expired invitation link'}, 400)

# Define the route to create an invitation
@app.route('/create_invitation', methods=['POST'])
def create_invitation():
    # Extract user input from the request
    sender_user_id = request.json.get('sender_user_id')
    receiver_user_id = request.json.get('receiver_user_id')
    channel_id = request.json.get('channel_id')

    # Create the invitation in the database
    invitation = create_invitation(sender_user_id, receiver_user_id, channel_id)

    return jsonify({'message': 'Invitation created successfully'})

@app.route('/verify_invitation', methods=['GET'])
def verify_invitation():
    channel_id = request.args.get('channel_id')
    token = request.args.get('token')

    if verify_invitation(channel_id, token):
        return jsonify({'message': 'Invitation is valid'})
    else:
        return jsonify({'message': 'Invalid or expired invitation link'}, 400)

# Create an Invitation
def create_invitation(sender_user_id, receiver_user_id, channel_id):
    # Generate a unique token for this invitation
    unique_token = secrets.token_urlsafe(16)  # Generate a 32-character URL-safe token

    # Create an Invitation record in the database
    invitation = Invitation(
        sender_user_id=sender_user_id,
        receiver_user_id=receiver_user_id,
        channel_id=channel_id,
        unique_token=unique_token,
        invitation_date=datetime.now()
    )
    db.session.add(invitation)
    db.session.commit()

    return invitation  # Return the invitation record

# Verify the Invitation
def verify_invitation(channel_id, token):
    # Query the database for the invitation
    invitation = Invitation.query.filter_by(channel_id=channel_id, unique_token=token).first()

    if invitation:
        # Invitation found, it's valid
        return True
    else:
        # Invitation not found, it's invalid
        return False
