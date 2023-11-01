from flask import jsonify, request,abort
from app import app, db
from flask_cors import CORS
<<<<<<< HEAD
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, Invitation,UserReport
import secrets
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity
from marshmallow import ValidationError
from validation import DataValidationSchema,SignupForm
from passlib.hash import sha256_crypt
=======
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, GroupChannel, GroupChatMessage, ImageMessage
import random
import string
from datetime import datetime
>>>>>>> 499b5b5f828905c04ae1ee98d13771baf9cb90ab


CORS(app)

@app.route('/')
def message():
    return 'welcome to the channels api'

# Initialize the JWT manager
jwt = JWTManager(app)

# Configure JWT settings 
app.config['JWT_SECRET_KEY'] = 'secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time

secret_key = secrets.token_hex(32)  # Generate a 64-character (32-byte) hex key
print(secret_key)

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

<<<<<<< HEAD
# Report user endpoint
@app.route('/report_user', methods=['POST'])
@jwt_required
def report_user():
    data = request.get_json()
    reporting_user_id = get_jwt_identity()
    reported_user_id = data.get('reported_user_id')
    reported_content_id = data.get('reported_content_id')

    # Validate the incoming data
    try:
        # You should create a schema for data validation, for example, using Marshmallow
        # Here's a simplified example:
        data_schema = DataValidationSchema()
        validated_data = data_schema.load(data)
    except ValidationError as err:
        return jsonify({"message": "Validation error", "error": err.messages}), 400

    # Additional validation
    if reporting_user_id == reported_user_id:
        return jsonify({"message": "You cannot report yourself"}), 400

    # Check if the reported user and content exist in your database
    reported_user = User.query.get(reported_user_id)
    if not reported_user:
        return jsonify({"message": "Reported user does not exist"}), 404

    # Check if the reported content exists
    reported_content = ReportedMessage.query.get(reported_content_id)
    if not reported_content:
        return jsonify({"message": "Reported content does not exist"}), 404

    return jsonify({"message": "Abuse reported successfully"}), 201

#Admin actions endpoint 
@app.route('/admin/reports', methods=['GET'])
@jwt_required
def list_reports():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_moderator:
        return jsonify({"message": "You do not have permission to access this endpoint."}), 403

    reports = Report.query.all()
    
    # Create a list of reports with their details and state
    report_list = [{"id": report.id, "user_id": report.user_id, "description": report.description, "state": report.state} for report in reports]
    
    return jsonify({"reports": report_list})

@app.route('/admin/reports/action', methods=['POST'])
@jwt_required
def report_action():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user or not current_user.is_moderator:
        return jsonify({"message": "You do not have permission to access this endpoint."}), 403

    data = request.get_json()
    report_id = data.get('report_id')
    action = data.get('action')
    
    report = Report.query.get(report_id)
    
    if not report:
        return jsonify({"message": "Report not found"}), 404
    
    if action == "resolve":
        report.state = "resolved"
    elif action == "reject":
        report.state = "rejected"
    elif action == "review":
        report.state = "under review"
    else:
        return jsonify({"message": "Invalid action"}), 400
    
    db.session.commit()
    
    return jsonify({"message": f"Report {report_id} has been {action}ed"})



# User signup endpoint 
@app.route('/signup', methods=['POST'])
def signup():
    form = SignupForm(request.form)
    if form.validate():
        username = form.username.data
        password = form.password.data
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 400
        
        # Hash the password before storing it
        hashed_password = sha256_crypt.hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User signed up successfully"}), 201
    else:
        return jsonify({"message": "Validation error", "errors": form.errors}), 400

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and sha256_crypt.verify(password, user.password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401
    
# Protected route 
from flask_jwt_extended import jwt_required

@app.route('/protected', methods=['GET'])
@jwt_required
def protected_route():
    # Only authenticated users can access this route
    return jsonify({"message": "You have access to this protected route"})
=======





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



# # Create an Image Message endpoint
# @app.route('/image_messages', methods=['POST'])
# def create_image_message():
#     # Extract data from the request
#     data = request.get_json()
#     print(data)
#     data = request.get_json()
#     channel_id = data.get('channel_id')
#     user_id = data.get('user_id')
#     image_url = data.get('image_url')
#     message_date = data.get('message_date')

#     # Create an ImageMessage object
#     new_image_message = ImageMessage(
#         channel_id=channel_id,
#         user_id=user_id,
#         image_url=image_url,
#         message_date=message_date
#     )

#     # # Add the image message to the database
#     db.session.add(new_image_message)
#     db.session.commit()
#     print(f"Channel ID: {channel_id}, User ID: {user_id}, Image URL: {image_url}, Message Date: {message_date}")

#     return jsonify({'message': 'Image message created successfully'})

from datetime import datetime

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





>>>>>>> 499b5b5f828905c04ae1ee98d13771baf9cb90ab

