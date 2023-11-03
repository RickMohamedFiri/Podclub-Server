from flask import jsonify, request,abort
from app import app, db
from flask_cors import CORS
from models import User, Channel, Message, GroupMessage, ReportedUser, ReportedMessage, Invitation,UserReport
import secrets
from datetime import timedelta
from flask_jwt_extended import JWTManager,jwt_required, get_jwt_identity
from marshmallow import ValidationError
from validation import DataValidationSchema
from passlib.hash import sha256_crypt


CORS(app)

@app.route('/')
def message():
    return 'welcome to the channels api'


# Create User endpoint
@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    user_name = data.get('user_name')
    email = data.get('email')
    password = data.get('password')

    if not user_name or not email or not password:
        return jsonify({'message': 'Please provide user_name, email, and password'}), 400

    existing_user = User.query.filter_by(user_name=user_name).first()

    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = sha256_crypt.hash(password)
    new_user = User(user_name=user_name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201
# Get all Users endpoint
@app.route('/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'user_name': user.user_name, 'email': user.email} for user in users]
    return jsonify(user_list)
# Update User endpoint
@app.route('/users/<int:user_id>', methods=['PATCH'])
@jwt_required
def update_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.id != current_user_id:
        return jsonify({'message': 'You can only update your own user profile'}), 403

    data = request.get_json()
    new_user_name = data.get('user_name')
    new_password = data.get('password')

    if new_user_name:
        user.user_name = new_user_name

    if new_password:
        user.password = sha256_crypt(salt=b"your_salt").hash(new_password)

    db.session.commit()
    return jsonify({'message': 'User profile updated successfully'})


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
    

    reports = UserReport.query.all()
    
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
    
    report = ReportedMessage.query.get(report_id)
    
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

# join multiple channels
@app.route('/accept-invitation/<int:invitation_id>', methods=['POST'])
def accept_invitation(invitation_id):
    user_id = get_jwt_identity()  # Get the user's ID from the JWT token
    invitation = Invitation.query.get(invitation_id)

    if invitation:
        if user_id == invitation.receiver_user_id:
            # Add the user to the channel associated with the invitation
            channel = Channel.query.get(invitation.channel_id)
            if channel:
                # Check if the user is already a member of the channel
                if user_id not in [member.user_id for member in channel.group_messages]:
                    new_group_message = GroupMessage(channel_id=channel.id, user_id=user_id)
                    db.session.add(new_group_message)
                    db.session.commit()
                    return jsonify({'message': 'Invitation accepted and user joined the channel successfully'})
                else:
                    return jsonify({'message': 'User is already a member of the channel'})
            else:
                return jsonify({'message': 'Channel not found'}, 404)
        else:
            return jsonify({'message': 'Unauthorized: You cannot accept this invitation'}, 403)
    else:
        return jsonify({'message': 'Invitation not found'}, 404)


