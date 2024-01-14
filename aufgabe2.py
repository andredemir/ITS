import hashlib
import json
import os
import time
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

OTLTIMEOUTSECONDS = 10
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
# Mapping von OTL codes zu offenen Regestrierungs Confirmations
pendingConfirmations = {}


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


def generate_otl_code(username, timestamp):
    return hashlib.sha256((username + str(timestamp)).encode()).hexdigest()


def set_otl_starttime(code, username, passhash, salt, timestamp):
    pendingConfirmations[code] = (username, passhash, salt, timestamp)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        if username not in users:
            salt = os.urandom(16).hex()
            hashed_password = hashlib.sha256((password_input + salt).encode()).hexdigest()

            # open new pending Confirmation for user
            timestamp = time.time()
            code = generate_otl_code(username, timestamp)
            set_otl_starttime(code, username, hashed_password, salt, timestamp)

            return """
                    <p>
                        Um ihre Regestrierung abzuschließen muss folgender Link geklickt werden
                    </p>
                    <p><a href="/confirm&code={code}">Regestrierung Bestätigen</a></p>
                """.format(code=code)

    return render_template('register.html')


@app.route('/confirm&code=<code>', methods=['GET'])
def confirm(code):
    if code in pendingConfirmations.keys():
        confirmtuple = pendingConfirmations[code]
        username = confirmtuple[0]
        passhash = confirmtuple[1]
        salt = confirmtuple[2]
        timestamp = confirmtuple[3]
        if round(time.time() - timestamp) < OTLTIMEOUTSECONDS:
            pendingConfirmations.pop(code)
            users[username] = {'password': passhash, 'salt': salt}
            save_users(users)
            return """
                                <p>
                                    Die Regestrierung war erfolgreich!
                                </p>
                                <p><a href="/login">Login</a></p>
                            """
    return """
                                <p>
                                    Der Link ist abgelaufen oder existiert nicht. Bitte regestrieren sie sich erneut.
                                </p>
                                <p><a href="/register">Regestrierung</a></p>
                            """


@app.route('/change_password', methods=['GET', 'POST'])
# @basic_auth.required  # Erfordert Basic Authentication für diese Route
def change_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        old_password = request.form['old_password']

        if username in users:
            stored_password, salt = users[username]['password'], users[username]['salt']
            hashed_password = hashlib.sha256((old_password + salt).encode()).hexdigest()

            if stored_password == hashed_password:
                salt = os.urandom(16).hex()
                hashed_password = hashlib.sha256((new_password + salt).encode()).hexdigest()

                users[username]['password'] = hashed_password
                users[username]['salt'] = salt
                save_users(users)

                return """
                    <p>
                        Passwort erfolgreich geändert
                    </p>
                    <p><a href="/">Zurück zur Startseite</a></p>
                """
            else:
                return """
                    <p>
                        Passwort stimmt nicht überein mit Ihrem alten
                    </p>
                    <p><a href="/change_password">Nochmal versuchen</a></p>
                """
        else:
            return """
                    <p>
                        Es gibt keinen Benutzer mit diesem Namen
                    </p>
                    <p><a href="/change_password">Nochmal versuchen</a></p>
                """

    return render_template('change_password.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


def check_otls():
    for key in pendingConfirmations.keys():
        # print("Im checking otls", time.gmtime().tm_sec)
        if round(time.time() - pendingConfirmations[key][3]) > OTLTIMEOUTSECONDS:
            pendingConfirmations.pop(key)


if __name__ == '__main__':
    # scheduler to manage otls
    cron = BackgroundScheduler(daemon=True)
    cron.add_job(check_otls, 'interval', seconds=OTLTIMEOUTSECONDS)
    cron.start()
    app.run(debug=True)
