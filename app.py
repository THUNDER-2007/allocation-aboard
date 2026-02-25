import os
import mysql.connector
from flask import Flask, request, render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# -----------------------------
# DATABASE CONNECTION
# -----------------------------
def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=os.getenv("DB_PORT", 3306)
    )

# -----------------------------
# HOME ROUTE
# -----------------------------
@app.route('/')
def home():
    return render_template("login.html")

# -----------------------------
# LOGIN ROUTE
# -----------------------------
@app.route('/login', methods=['POST'])
def login():

    username = request.form.get("username")
    password = request.form.get("password")
    honeypot = request.form.get("hidden_field")
    load_time = float(request.form.get("load_time", 0))

    ip_address = request.remote_addr

    # -----------------------------
    # 🍯 HONEYPOT CHECK
    # -----------------------------
    if honeypot:
        return "Bot detected (Honeypot triggered)"

    # -----------------------------
    # ⏱ TIME ANALYSIS CHECK
    # -----------------------------
    if load_time < 2:
        return "Suspicious activity detected (Too fast submission)"

    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return "Invalid username or password"

    # -----------------------------
    # 🔒 ACCOUNT LOCK CHECK
    # -----------------------------
    if user["lock_until"] and user["lock_until"] > datetime.now():
        return "Account locked. Try again later."

    # -----------------------------
    # 🔑 PASSWORD VERIFICATION
    # -----------------------------
    if check_password_hash(user["password_hash"], password):

        cursor.execute("""
            UPDATE users 
            SET failed_attempts = 0, lock_until = NULL 
            WHERE username = %s
        """, (username,))
        db.commit()

        session["user"] = username
        return "Login Successful!"

    else:
        failed_attempts = user["failed_attempts"] + 1
        lock_until = None

        # -----------------------------
        # 🚨 BRUTE FORCE PROTECTION
        # -----------------------------
        if failed_attempts >= 5:
            lock_until = datetime.now() + timedelta(minutes=10)

        cursor.execute("""
            UPDATE users 
            SET failed_attempts = %s, lock_until = %s 
            WHERE username = %s
        """, (failed_attempts, lock_until, username))
        db.commit()

        return "Invalid username or password"

# -----------------------------
# REGISTER ROUTE
# -----------------------------
@app.route('/register', methods=['POST'])
def register():

    username = request.form.get("username")
    password = request.form.get("password")

    hashed_pw = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        INSERT INTO users (username, password_hash)
        VALUES (%s, %s)
    """, (username, hashed_pw))

    db.commit()
    return "User Registered Successfully!"

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)