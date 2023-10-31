# app.py
from flask import Flask 
from config import Config
from models import db
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager
from datetime import timedelta



app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

# Initialize the JWT manager
jwt = JWTManager(app)

# Configure JWT settings (Note: Store your secret key securely, not hardcoded here)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time

# Import routes after JWT configuration
from routes import *



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
