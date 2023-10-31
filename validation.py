from marshmallow import Schema, fields
from wtforms import Form, StringField, PasswordField, validators

class DataValidationSchema(Schema):
    reported_user_id = fields.Integer(required=True)
    reported_content_id = fields.Integer(required=True)

# User sign up
class SignupForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=80), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=6), validators.DataRequired()])
