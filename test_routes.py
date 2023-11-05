import json
import pytest
from app import app, db  

@pytest.fixture
def client():
    # Create a test client using the app's test config
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Define test cases for the /users endpoint
def test_create_user(client):
    data = {
        'user_name': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword'
    }
    response = client.post('/users', json=data)
    assert response.status_code == 200
    assert b'User created successfully' in response.data

def test_get_all_users(client):
    response = client.get('/users')
    assert response.status_code == 200
    assert b'testuser' in response.data

# Define test cases for the /channels endpoint
def test_create_channel(client):
    data = {
        'name': 'Test Channel',
        'description': 'Test Channel Description',
        'user_id': 1  # Provide a valid user ID
    }
    response = client.post('/channels', json=data)
    assert response.status_code == 200
    assert b'Channel created successfully' in response.data

def test_get_all_channels(client):
    response = client.get('/channels')
    assert response.status_code == 200
    assert b'Test Channel' in response.data

# Add more test cases for other endpoints as needed
