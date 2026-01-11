from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Secret key
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')

# MySQL Configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL
mysql = MySQL(app)

# ---------------- LOGIN ----------------
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        cursor = mysql.connection.cursor()
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s',
            (username,)
        )
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return render_template('index.html', msg='Logged in successfully!')
        else:
            msg = 'Incorrect username or password!'

    return render_template('login.html', msg=msg)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        cursor = mysql.connection.cursor()

        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s OR email = %s',
            (username, email)
        )
        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'^[A-Za-z0-9_]+$', username):
            msg = 'Username must contain only letters, numbers and underscore!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            hashed_password = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO accounts (username, email, password)
                VALUES (%s, %s, %s)
                """,
                (username, email, hashed_password)
            )
            mysql.connection.commit()
            msg = 'You have successfully registered!'

    return render_template('register.html', msg=msg)

# ---------------- RUN APP ----------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
