import secrets
from flask import jsonify, request,abort,redirect, render_template, url_for
from flask_jwt_extended import JWTManager
from app import app, db, mail 
from flask_cors import CORS
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, GroupChannel, GroupChatMessage, ImageMessage, Invitation
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

# Create User endpoint

@app.route('/users', methods=['POST', 'PUT'])
def create_or_update_user():
    if request.method == 'POST':
        new_user = User(
            user_name=request.json.get('user_name'),
            email=request.json.get('email'),
            password=request.json.get('password')
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'})
    elif request.method == 'PUT':
        # Handle PUT request logic 
        return jsonify({'message': 'User data updated successfully'})
    return 'welcome to the channels api'


# Create User endpoint
@app.route('/users', methods=['POST'])
def create_user():
    new_user = User(user_name=request.json['user_name'], email=request.json['email'], password=request.json['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

# Get all Users endpoint
@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'user_name': user.user_name, 'email': user.email} for user in users]
    return jsonify(user_list)

# Update User endpoint
@app.route('/users/<int:user_id>', methods=['PATCH'])
def update_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.user_name = request.json.get('user_name', user.user_name)
        user.email = request.json.get('email', user.email)
        user.password = request.json.get('password', user.password)
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    else:
        return jsonify({'message': 'User not found'}, 404)

# Create Channel endpoint
@app.route('/channels', methods=['POST'])
def create_channel():
    new_channel = Channel(name=request.json['name'], description=request.json['description'], user_id=request.json['user_id'])
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
    new_message = Message(message=request.json['message'], user_id=request.json['user_id'], channel_id=request.json['channel_id'])
    db.session.add(new_message)
    db.session.commit()
    return jsonify({'message': 'Message created successfully'})

#  All Messages endpoint
@app.route('/messages', methods=['GET'])
def get_all_messages():
    messages = Message.query.all()
    message_list = [{'id': message.id, 'message': message.message, 'user_id': message.user_id, 'channel_id': message.channel_id} for message in messages]
    return jsonify(message_list)

# Update Message endpoint
@app.route('/messages/<int:message_id>', methods=['PATCH'])
def update_message(message_id):
    message = Message.query.get(message_id)
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
    message = Message.query.get(message_id)
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
    new_reported_user = ReportedUser(reporting_user_id=request.json['reporting_user_id'], reported_user_id=request.json['reported_user_id'], message_id=request.json['message_id'], is_banned=request.json['is_banned'])
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
# @app.route('/group_channels', methods=['POST'])
# def create_group_channel():
#     user_id = request.json.get('user_id')
#     # Check if the user has reached the maximum limit of group channels (e.g., 5).
#     user = User.query.get(user_id)
#     if user and user.group_channels_count < 5:
#         # The user can create a new group channel. Increment the group_channels_count.
#         user.group_channels_count += 1
#         new_channel = GroupChannel(user_id=user_id, channel_name=request.json['channel_name'], description=request.json['description'])
#         db.session.add(new_channel)
#         db.session.commit()
#         return jsonify({'message': 'Group channel created successfully'})
#     else:
#         return jsonify({'message': 'Maximum limit of group channels reached for this user'}, 403)

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

# 
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



## Authentication

# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form['email']
#     password = request.form['password']

#     user = User.query.filter_by(email=email).first()
#     if user and check_password_hash(user.password, password):
#         login_user(user)  # Log in the user
#         return jsonify({'message': 'Login successful'})

#     return jsonify({'message': 'Invalid email or password'}, 401)

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        # Generate an access token
        access_token = create_access_token(identity=user.id)  # Use the user's ID as the identity

        # Log in the user
        login_user(user)

        # Include the access token in the response
        return jsonify({'access_token': access_token, 'message': 'Login successful'})

    return jsonify({'message': 'Invalid email or password'}, 401)


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Extract user registration data from the JSON data
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')

    # Check if the email is not already in use
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already in use'}, 409)

    # Create a new user with the hashed password
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=generate_password_hash(password, method='pbkdf2:sha256')
    )
    db.session.add(new_user)
    db.session.commit()

    # Log in the newly registered user
    login_user(new_user)

    return jsonify({'message': 'User registered and logged in'})

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




# @app.route('/send_invitation_email', methods=['POST'])
# def send_invitation_email():
#     if request.method == 'POST':
#         recipient_email = request.json.get('recipient_email')
#         channel_id = request.json.get('channel_id')
#         invitation_link = f'http://127.0.0.1:5001/invitations/{channel_id}/accept'

#         # Create an email message
#         subject = 'You are invited to join our group channel'
#         body = f'Click the following link to join our group channel: {invitation_link}'
#         sender = 'yusramoham99@gmail.com'  # Replace with your email address
#         recipients = [recipient_email]

#         msg = Message(subject=subject, sender=sender, recipients=recipients)
#         msg.body = body

#         try:
#             mail.send(msg)
#             return jsonify({'message': 'Invitation email sent successfully'})
#         except Exception as e:
#             return jsonify({'message': f'Failed to send the invitation email: {str(e)}'}, 500)

#     return jsonify({'message': 'Invalid request'}, 400)

@app.route('/send_invitation_email', methods=['POST'])
def send_invitation_email():
    if request.method == 'POST':
        recipient_email = request.json.get('recipient_email')
        channel_id = request.json.get('channel_id')
        
        # Generate a unique token for this invitation
        unique_token = secrets.token_urlsafe(16)  # Generate a 32-character URL-safe token
        
        # Create the invitation link with the unique token
        invitation_link = f'http://127.0.0.1:5001/invitations/{channel_id}/accept?token={unique_token}'

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


# # Add this route to your application
# @app.route('/accept_invitation/<token>', methods=['GET'])
# def accept_invitation(token):
#     # Find the invitation with the provided token
#     invitation = Invitation.query.filter_by(token=token).first()

#     if invitation:
#         # Check if the invitation is not expired (if you have an expiration check)
#         # Check if the recipient is not already a member of the group

#         # Associate the user with the group channel
#         user = User.query.filter_by(email=invitation.recipient_email).first()
#         if user:
#             group_channel = GroupChannel.query.get(invitation.group_channel_id)
#             if group_channel:
#                 user.group_channels.append(group_channel)
#                 db.session.commit()

#             # You can also delete the invitation if needed
#             db.session.delete(invitation)
#             db.session.commit()

#             return redirect(url_for('group_channel_page', channel_id=group_channel.id))
#         else:
#             return jsonify({'message': 'User not found'}, 404)
#     else:
#         return jsonify({'message': 'Invalid or expired invitation link'}, 400)


@app.route('/accept_invitation/<token>', methods=['GET'])
def accept_invitation(token):
    print(f"Received invitation token: {token}")  # Debugging statement

    # Find the invitation with the provided token
    invitation = Invitation.query.filter_by(token=token).first()
    if invitation:
        print(f"Invitation found: {invitation.id}")  # Debugging statement

        # Check if the invitation is not expired (if you have an expiration check)
        # Debugging statement for expiration check:
        if invitation.is_expired:
            print("Invitation is expired")
            return jsonify({'message': 'Invitation has expired'}, 400)

        # Check if the recipient is not already a member of the group
        user = User.query.filter_by(email=invitation.recipient_email).first()
        if user:
            print(f"User found: {user.id}")  # Debugging statement
            group_channel = GroupChannel.query.get(invitation.group_channel_id)
            if group_channel:
                user.group_channels.append(group_channel)
                db.session.commit()
                print(f"User added to group channel: {group_channel.id}")  # Debugging statement
            else:
                print("Group channel not found")  # Debugging statement
        else:
            print("User not found")  # Debugging statement
            return jsonify({'message': 'User not found'}, 404)
    else:
        print("Invalid or expired invitation link")  # Debugging statement
        return jsonify({'message': 'Invalid or expired invitation link'}, 400)

    return redirect(url_for('group_channel_page', channel_id=group_channel.id))
