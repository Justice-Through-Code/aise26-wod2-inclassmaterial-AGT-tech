# Simple Python API - Starting Point for GitHub Classroom Assignment
# This code has intentional security flaws for educational purposes

from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

load_dotenv() # Load variables from .env into environment

app = Flask(__name__)

# Load secrets from environment 
DATABASE_URL = os.getenv("DATABASE_URL")
API_SECRET = os.getenv("API_SECRET")
debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

def get_db_connection():
    conn=sqlite3.connect('users.db')
    conn.row_factory =sqlite3.Row
    return conn 

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy", 
        "database_configured": bool(DATABASE_URL),
        "api_secret_configured": bool(API_SECRET)
    })

@app.route('/users', methods=['GET'])
def get_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()
    return jsonify({"users": [{'id': u['id'],"username": u['username']} for u in users]})

@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'username and password required'}), 400
    
    # Secure password hashing (PBKDF2 using werkzeug)
    hashed_password = generate_password_hash(password)

    
    conn = get_db_connection()
    try:

        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "username already exists"}), 409
    conn.close()
    
    # Log only non-sensitive info.
    app.logger.info("Created user: %s", username)
    return jsonify({"message": "User created", "username": username}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "username and password required"}), 400
    
    hashed_password = generate_password_hash(password)

    
    conn = get_db_connection()
    user = conn.execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user["password"], password):
        return jsonify({"message": "Login successful", "user_id": user['id']})
    return jsonify({"message": "Invalid credentials"}), 401

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=debug_mode)