from flask import jsonify, request
from app import app, db
from flask_cors import CORS
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, Invitation

CORS(app)

@app.route('/')
def message():
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

