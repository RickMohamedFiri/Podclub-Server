# Podclub Server

Podclub is a social platform for sharing podcasts and discussing topics. This server application provides the backend for the Podclub platform.

## Features

- User authentication and authorization
- User registration and profile management
- Channel creation and management
- Reporting and unbanning users
- Group channel moderation

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.8 or higher
- Virtual environment (optional but recommended)

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/RickMohamedFiri/Podclub-Server.git

2. Change to the project directory:

      cd   Podclub-server

3. Activate the virtual environment:

      source venv/bin/activate

4. Install project dependencies:

      pip install -r requirements.txt

5. Initialize the database:

      flask db init
      flask db migrate
      flask db upgrade

6. Run the application:

      flask run

## API Endpoints

### 1. Authenticate User

- **URL:** `/api/authenticate`
- **Method:** POST
- **Description:** Authenticate a user and generate an access token.
- **Request:**
  - Body:
    - `email` (string, required): User's email address.
    - `password` (string, required): User's password.
- **Response:**
  - Status Code: 200 OK
  - Body:
    - `access_token` (string): JWT access token for the authenticated user.

### 2. Create User

- **URL:** `/api/users`
- **Method:** POST
- **Description:** Create a new user.
- **Request:**
  - Body:
    - `email` (string, required): User's email address.
    - `password` (string, required): User's password.
    - `first_name` (string, required): User's first name.
    - `last_name` (string, required): User's last name.
- **Response:**
  - Status Code: 201 Created
  - Body:
    - `message` (string): User created successfully.

### 3. Get User Profile

- **URL:** `/api/users/<user_id>`
- **Method:** GET
- **Description:** Get a user's profile information.
- **Request:**
  - URL Parameters:
    - `user_id` (integer, required): User's ID.
- **Response:**
  - Status Code: 200 OK
  - Body:
    - `user` (object): User's profile information.

### 4. List Channels

- **URL:** `/api/channels`
- **Method:** GET
- **Description:** Get a list of all available channels.
- **Response:**
  - Status Code: 200 OK
  - Body:
    - `channels` (array of objects): List of available channels.

### 5. Create Channel

- **URL:** `/api/channels`
- **Method:** POST
- **Description:** Create a new channel.
- **Request:**
  - Body:
    - `name` (string, required): Channel name.
    - `description` (string, required): Channel description.
- **Response:**
  - Status Code: 201 Created
  - Body:
    - `message` (string): Channel created successfully.

### 6. Delete Channel

- **URL:** `/api/channels/<channel_id>`
- **Method:** DELETE
- **Description:** Delete a channel by ID.
- **Request:**
  - URL Parameters:
    - `channel_id` (integer, required): Channel ID to be deleted.
- **Response:**
  - Status Code: 204 No Content
  - Body: No content.

### 7. Report User

- **URL:** `/api/report/user`
- **Method:** POST
- **Description:** Report a user for abusive behavior.
- **Request:**
  - Body:
    - `reported_user_id` (integer, required): ID of the user being reported.
    - `message_id` (integer, required): ID of the message associated with the report.
- **Response:**
  - Status Code: 201 Created
  - Body:
    - `message` (string): User reported successfully.

### 8. Unban User

- **URL:** `/api/unban/user`
- **Method:** PUT
- **Description:** Unban a previously reported user.
- **Request:**
  - Body:
    - `reported_user_id` (integer, required): ID of the reported user to unban.
- **Response:**
  - Status Code: 200 OK
  - Body:
    - `message` (string): User unbanned successfully.

## Contributing

If you'd like to contribute to this project, please fork the repository, create a new branch, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.

## Contact

For questions or feedback, please feel free to reach out to:

Alex-gikungu | yusram99 | mukasa36
