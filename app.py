import os
import mysql.connector
from flask import Flask, request, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# DATABASE CONNECTION
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT", 3306))
    )

@app.route('/')
def home():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():

    username = request.form.get("username")
    password = request.form.get("password")
    honeypot = request.form.get("hidden_field")
    load_time = float(request.form.get("load_time", 0))

    # Honeypot
    if honeypot:
        return "Bot detected"

    # Time analysis
    if load_time < 2:
        return "Suspicious activity detected"

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if not user:
        cursor.close(); db.close()
        return "Invalid username or password"

    if user["lock_until"] and user["lock_until"] > datetime.now():
        cursor.close(); db.close()
        return "Account locked. Try later"

    if check_password_hash(user["password_hash"], password):

        cursor.execute("""
            UPDATE users 
            SET failed_attempts=0, lock_until=NULL 
            WHERE username=%s
        """, (username,))
        db.commit()
        cursor.close(); db.close()

        session["user"] = username
        return "Login Successful"

    else:
        failed = user["failed_attempts"] + 1
        lock_until = None

        if failed >= 5:
            lock_until = datetime.now() + timedelta(minutes=10)

        cursor.execute("""
            UPDATE users 
            SET failed_attempts=%s, lock_until=%s 
            WHERE username=%s
        """, (failed, lock_until, username))
        db.commit()
        cursor.close(); db.close()

        return "Invalid username or password"

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    hashed = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (%s, %s)
    """, (username, hashed))

    db.commit()
    cursor.close(); db.close()

    return "User Registered"

if __name__ == "__main__":
    app.run()
