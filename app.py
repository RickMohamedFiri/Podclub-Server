# app.py
import os
import secrets
from flask import Flask 
from config import Config
from models import db
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager
from datetime import timedelta
from flask_mail import Mail
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity


app = Flask(__name__)
# Set the secret key
app.config['SECRET_KEY'] = '234567qwertyuuio'
# Configure JWT settings (Note: Store your secret key securely, not hardcoded here)
app.config['JWT_SECRET_KEY'] = '1234567880087qwertyxk'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"  # Set the view name for the login page
login_manager.init_app(app)


# Define the user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

jwt = JWTManager(app)


# Configure Flask-Mail for sending email notifications
mail = Mail(app)

# Configure Flask-Mail for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = "yusramoham99@gmail.com"
app.config['MAIL_PASSWORD'] = 'podclub'
app.config['MAIL_USE_TLS'] = True



secret_key = secrets.token_hex(32)  # Generate a 64-character (32-byte) hex key
print(secret_key)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

