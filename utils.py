# utils.py

import secrets

def generate_unique_token():
    token = secrets.token_hex(16)  # You can adjust the token length as needed
    return token

git clean -f
git checkout origin/development -- __pycache__/app.cpython-38.pyc
git checkout origin/development -- __pycache__/config.cpython-38.pyc
git checkout origin/development -- __pycache__/models.cpython-38.pyc


git add __pycache__/app.cpython-38.pyc
git add __pycache__/config.cpython-38.pyc
git add __pycache__/models.cpython-38.pyc -f



git add __pycache__/file-name.cpython-38.pyc


git merge --continue
