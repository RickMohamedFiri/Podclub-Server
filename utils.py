# utils.py

import secrets

def generate_unique_token():
    token = secrets.token_hex(16)  # You can adjust the token length as needed
    return token

