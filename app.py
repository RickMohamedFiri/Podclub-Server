# app.py
from flask import Flask 
from config import Config
from models import db
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager
from datetime import timedelta
import secrets

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

jwt = JWTManager(app)

# Configure JWT settings 
app.config['JWT_SECRET_KEY'] = 'secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time

secret_key = secrets.token_hex(32)  # Generate a 64-character (32-byte) hex key
print(secret_key)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
