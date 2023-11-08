import json
import pytest
from app import app, db
from models import *

# Define a fixture to set up a test client and a test database
@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()    

# Define a test for the signup endpoint
def test_signup(client):
    # Prepare a JSON payload for the POST request
    data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'johndoe@example.com',
        'password': 'password123'
    }

    # Send a POST request to the signup endpoint
    response = client.post('/signup', data=json.dumps(data), content_type='application/json')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Parse the response JSON
    result = json.loads(response.data)

    # Check if the response message contains 'User registered and logged in'
    assert 'User registered and logged in' in result.get('message', '')

# Define a test for the login endpoint
def test_login(client):
    # Create a test user in the database
    hashed_password = generate_password_hash('password123', method='pbkdf2:sha256')
    test_user = User(email="johndoe@example.com", password=hashed_password)
    with app.app_context():
        db.session.add(test_user)
        db.session.commit()

    # Prepare a JSON payload for the POST request
    data = {
        'email': 'johndoe@example.com',
        'password': 'password123'
    }

    # Send a POST request to the login endpoint
    response = client.post('/login', data=json.dumps(data), content_type='application/json')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Parse the response JSON
    result = json.loads(response.data)

    # Check if the response message contains 'Login successful'
    assert 'Login successful' in result.get('message', '')


def test_get_all_users(client):
    # Create test users in the database with valid passwords
    test_user1 = User(user_name="user1", email="user1@example.com", password="password1")
    test_user2 = User(user_name="user2", email="user2@example.com", password="password2")
    with app.app_context():
        db.session.add(test_user1)
        db.session.add(test_user2)
        db.session.commit()

    # Send a GET request to the 'get_all_users' endpoint
    response = client.get('/users')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Parse the response JSON
    result = json.loads(response.data)

    # Check if the response contains user data
    assert len(result) == 2  # Assuming there are 2 test users in the database

def test_create_channel(client):
    # Define test data for creating a channel
    data = {
        'name': 'Test Channel',
        'description': 'This is a test channel description',
        'user_id': 1  # Replace with a valid user ID
    }

    # Send a POST request to the /channels endpoint
    response = client.post('/channels', json=data)

    # Check if the response status code is 200 (success)
    assert response.status_code == 200

    # Check if the response message indicates success
    assert 'Channel created successfully' in response.json['message']

def test_get_all_channels(client):
    # Create a test channel
    with app.app_context():
        test_channel = Channel(name='Test Channel', description='This is a test channel description', user_id=1)
        db.session.add(test_channel)
        db.session.commit()

    # Send a GET request to the /channels endpoint
    response = client.get('/channels')

    # Check if the response status code is 200 (success)
    assert response.status_code == 200

    # Check if the response contains the test channel data
    assert any(channel['name'] == 'Test Channel' for channel in response.json)

def test_update_channel(client):
    # Create a test channel
    with app.app_context():
        test_channel = Channel(name='Test Channel', description='This is a test channel description', user_id=1)
        db.session.add(test_channel)
        db.session.commit()

    # Define the data for updating the channel
    data = {
        'name': 'Updated Channel Name',
        'description': 'Updated description',
        'user_id': 2  # Replace with the new user ID
    }

    # Send a PATCH request to update the channel
    response = client.patch('/channels/1', json=data)

    # Check if the response status code is 200 (success)
    assert response.status_code == 200

    # Check if the response message indicates success
    assert 'Channel updated successfully' in response.json['message']

    # Check if the channel has been updated
    updated_channel = Channel.query.get(1)
    assert updated_channel.name == 'Updated Channel Name'
    assert updated_channel.description == 'Updated description'
    assert updated_channel.user_id == 2

def test_create_message(client):
    # Define data for creating a new message
    data = {
        'message': 'Test message',
        'user_id': 1,
        'channel_id': 1
    }

    # Send a POST request to create a new message
    response = client.post('/messages', json=data)

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

def test_get_all_messages(client):
    with app.app_context():  # Create an application context here
        # Create some test messages in the database
        test_messages = [
            Messages(message='Message 1', user_id=1, channel_id=1),
            Messages(message='Message 2', user_id=2, channel_id=1),
            Messages(message='Message 3', user_id=1, channel_id=2)
        ]

        for message in test_messages:
            db.session.add(message)

        db.session.commit()

        # Send a GET request to retrieve all messages
        response = client.get('/messages')

        # Check if the response status code is 200 (OK)
        assert response.status_code == 200

        # Check if the response contains the test messages
        data = json.loads(response.data)
        assert len(data) == len(test_messages)

        for i, message in enumerate(test_messages):
            assert data[i]['message'] == message.message



def test_delete_message(client):
    # Create a test message in the database
    with app.app_context():
        test_message = Messages(message='Test Message', user_id=1, channel_id=1)
        db.session.add(test_message)
        db.session.commit()

    with app.app_context():
        # Delete the message using the SQLAlchemy session
        db.session.delete(test_message)
        db.session.commit()

    # Check if the message was deleted from the database
    with app.app_context():
        deleted_message = Messages.query.get(test_message.id)
        assert deleted_message is None


def test_create_group_message(client):
    # Prepare a JSON payload for the request
    payload = {
        'channel_id': 1,  # Replace with a valid channel_id
        'user_id': 1,     # Replace with a valid user_id
    }

    # Send a POST request to create a group message
    response = client.post('/group_messages', json=payload)

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response JSON contains the expected message
    data = response.get_json()
    assert data['message'] == 'Group message created successfully'

def test_get_all_group_messages(client):
    # Send a GET request to retrieve all group messages
    response = client.get('/group_messages')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response JSON contains a list of group messages
    data = response.get_json()
    assert isinstance(data, list)

    # Optionally, you can check the structure of each group message in the list
    for group_message in data:
        assert 'id' in group_message
        assert 'channel_id' in group_message
        assert 'user_id' in group_message
        

def test_create_reported_user(client):
    # Define a sample reported user data
    reported_user_data = {
        'reporting_user_id': 1,
        'reported_user_id': 2,
        'message_id': 3,
        'is_banned': True
    }

    # Send a POST request to create a reported user
    response = client.post('/reported_users', json=reported_user_data)

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the reported user has been created successfully
    reported_user = json.loads(response.data)
    assert 'message' in reported_user
    assert reported_user['message'] == 'Reported user created successfully'

def test_get_all_reported_users(client):
    # Send a GET request to retrieve all reported users
    response = client.get('/reported_users')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response data contains a list of reported users
    reported_users = json.loads(response.data)
    assert isinstance(reported_users, list)

   # check if the data structure matches the expected format
    for reported_user in reported_users:
        assert 'id' in reported_user
        assert 'reporting_user_id' in reported_user
        assert 'reported_user_id' in reported_user
        assert 'message_id' in reported_user
        assert 'is_banned' in reported_user


def test_create_group_channel(client):
    # Define data for creating a group channel
    group_channel_data = {
        'user_id': 1,
        'channel_name': 'Test Channel',
        'description': 'This is a test channel',
    }

    # Send a POST request to create a group channel
    response = client.post('/group_channels', json=group_channel_data)

    # Check if the response status code is 200 (OK) and if the response message is as expected
    assert response.status_code == 200
    assert json.loads(response.data)['message'] == 'Group channel created successfully'

def test_get_group_channels(client):
    # Send a GET request to retrieve group channels
    response = client.get('/group_channels')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response contains data for group channels
    group_channels = json.loads(response.data)
    assert isinstance(group_channels, list)  # Ensure it's a list of channels

    # You can add more specific assertions based on your data model
    # For example, check if the retrieved channels match the expected data

    # Example: Check if the first channel's name matches
    if group_channels:
        first_channel = group_channels[0]
        assert 'channel_name' in first_channel
        assert first_channel['channel_name'] == 'Test Channel'


def test_add_message_to_group_chat(client):
    # Define a sample message to add to the group chat
    sample_message = {
        'user_id': 1,  # Replace with a valid user ID
        'message_content': 'Hello, this is a test message',
        'channel_id': 1  # Replace with a valid channel ID
    }

    # Send a POST request to add the message to the group chat
    response = client.post('/group_chat_messages', json=sample_message)

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response contains the success message
    response_data = json.loads(response.data)
    assert 'message' in response_data
    assert response_data['message'] == 'Message added to the group chat'

def test_get_group_chat_messages(client):
    # Send a GET request to retrieve group chat messages
    response = client.get('/group_chat_messages')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response contains a list of group chat messages
    response_data = json.loads(response.data)
    assert isinstance(response_data, list)

def test_get_reported_messages(client):
    # Create some sample reported messages in the database
    sample_messages = [
        {
            'reporting_user_id': 1,
            'user_id': 2,
            'message_id': 3,
            'report_date': datetime.strptime('2023-11-07 14:30:00', '%Y-%m-%d %H:%M:%S'),  # Convert to datetime
            'is_banned': True
        },
        {
            'reporting_user_id': 2,
            'user_id': 3,
            'message_id': 4,
            'report_date': datetime.strptime('2023-11-08 15:45:00', '%Y-%m-%d %H:%M:%S'),  # Convert to datetime
            'is_banned': False
        }
    ]

    with app.app_context():
        for message_data in sample_messages:
            db.session.add(ReportedMessage(**message_data))
        db.session.commit()

    # Send a GET request to retrieve reported messages
    response = client.get('/reported_messages')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response contains a JSON array of reported messages
    reported_messages = json.loads(response.get_data(as_text=True))
    assert isinstance(reported_messages, list)

    # Check if the expected reported messages are present in the response
    assert len(reported_messages) == len(sample_messages)

# Test the 'create_image_message' endpoint
def test_create_image_message(client):
    # Define sample data for creating an image message
    image_message_data = {
        'channel_id': 1,
        'user_id': 1,
        'image_url': 'https://example.com/image.jpg',
        'message_date': '2023-11-07 14:30:00.000000'
    }

    # Send a POST request to create the image message
    response = client.post('/image_messages', json=image_message_data)

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response message indicates success
    response_data = json.loads(response.get_data(as_text=True))
    assert 'message' in response_data
    assert response_data['message'] == 'Image message created successfully'

# Test the 'get_image_messages' endpoint
def test_get_image_messages(client):
    # Send a GET request to retrieve image messages
    response = client.get('/image_messages')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the response contains a JSON array of image messages
    image_messages = json.loads(response.get_data(as_text=True))
    assert isinstance(image_messages, list)

    # Optional: Check the structure of the returned image messages
    for message in image_messages:
        assert 'channel_id' in message
        assert 'user_id' in message
        assert 'image_url' in message
        assert 'message_date' in message


# Clean up the test database after running the tests
def teardown_function():
    with app.app_context():
        db.drop_all()