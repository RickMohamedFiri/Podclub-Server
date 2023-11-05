import json
import pytest
from app import app, db
from models import User

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
        'last_name': 'testuser',
        'first_name': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword'
    }
    response = client.post('/users', json=data)
    assert response.status_code == 200
    assert b'User created successfully' in response.data

def test_get_all_users(client):
    with app.app_context():
        # Create some test users or fetch them from the database
        user1 = User(user_name='Alice', email='alice@example.com', password='password1')
        user2 = User(user_name='Bob', email='bob@example.com', password='password2')
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        response = client.get('/users')
        data = response.get_json()

        # Make assertions about the response data
        assert len(data) == 2  # Assuming you have two users

        # You can access user attributes like this
        assert data[0]['user_name'] == 'Alice'
        assert data[1]['email'] == 'bob@example.com'

def test_update_user(client):
    with app.app_context():
        # Create a test user
        test_user = User(user_name='TestUser', email='test@example.com', password='testpassword')
        db.session.add(test_user)
        db.session.commit()

        # Login and get an access token
        data = {
            'user_name': 'TestUser',
            'password': 'testpassword'
        }
        login_response = client.post('/login', json=data)
        access_token = login_response.get_json()['access_token']

        # Prepare updated data
        updated_data = {
            'user_name': 'UpdatedUser',
            'password': 'updatedpassword'
        }

        # Send a PATCH request to update the user's profile
        response = client.patch('/users', json=updated_data, headers={'Authorization': f'Bearer {access_token}'})
        assert response.status_code == 200
        assert b'User profile updated successfully' in response.data

        # Verify that the user's profile is updated in the database
        updated_user = User.query.filter_by(user_name='UpdatedUser').first()
        assert updated_user is not None
        assert updated_user.check_password('updatedpassword')

# # Add more test cases for other endpoints as needed
