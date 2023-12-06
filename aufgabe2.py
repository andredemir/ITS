from flask import Flask, render_template, request, redirect, url_for, session
import os
import hashlib
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

USERS_FILE = 'users.json'

def load_users():
    try:
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_users(users_data):
    with open(USERS_FILE, 'w') as file:
        json.dump(users_data, file, indent=2)

# Dummy-Benutzerdaten laden
users = load_users()

@app.route('/')
def index():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        if username in users:
            stored_password, salt = users[username]['password'], users[username]['salt']
            hashed_password = hashlib.sha256((password_input + salt).encode()).hexdigest()

            if stored_password == hashed_password:
                session['username'] = username
                return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        if username not in users:
            salt = os.urandom(16).hex()
            hashed_password = hashlib.sha256((password_input + salt).encode()).hexdigest()

            users[username] = {'password': hashed_password, 'salt': salt}
            save_users(users)
            
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)