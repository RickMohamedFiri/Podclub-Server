from flask import Flask
from config import Config
from models import db
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager, create_access_token
from datetime import timedelta
from wtforms import Form, StringField, PasswordField, validators
from flask import jsonify, request, abort
from passlib.hash import sha256_crypt
import os
from models import User
import secrets

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)


# Initialize the JWT manager
jwt = JWTManager(app)

# Configure JWT settings 
app.config['JWT_SECRET_KEY'] = 'secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expiration time

secret_key = secrets.token_hex(32)  # Generate a 64-character (32-byte) hex key
print(secret_key)

# User sign up
class SignupForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=80), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=6), validators.DataRequired()])

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

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
