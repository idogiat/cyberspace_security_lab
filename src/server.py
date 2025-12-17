from flask import Flask, render_template, request, jsonify, redirect, session, url_for
from datetime import timedelta, datetime
import json
import sys
import os

# Ensure src is on path so imports work when running from repo root
sys.path.insert(0, os.path.dirname(__file__))

from Database import DB

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-change-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Initialize database (Database.py handles check_same_thread=False)
db = DB()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        hash_mode = data.get('hash_mode', 'bcrypt')  # default to bcrypt

        if not username or len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400

        if not password or len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

        # Check if user exists using database
        if db.user_exists(username):
            return jsonify({'success': False, 'message': 'Username already exists'}), 409

        # Register user in database with hashing
        try:
            db.register(username, password, hash_mode)
        except Exception as e:
            # if DB raised IntegrityError it bubbles up - return conflict
            return jsonify({'success': False, 'message': str(e)}), 500

        return jsonify({'success': True, 'message': 'Registration successful. Please login.', 'username': username}), 201

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        # Get client info for logging
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')

        if not username or not password:
            db.log_login_attempt(username or 'unknown', 'failed', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'Username and password required'}), 400

        # Verify login using database
        if not db.login(username, password):
            db.log_login_attempt(username, 'failed', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

        # Login successful
        session['username'] = username
        session.permanent = True
        db.log_login_attempt(username, 'success', client_ip, user_agent)

        return jsonify({'success': True, 'message': 'Login successful', 'username': username, 'redirect': '/dashboard'}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    username = session.get('username', 'unknown')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    db.log_login_attempt(username, 'logout', client_ip, user_agent)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'}), 200

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'Server is running'}), 200

@app.route('/api/user', methods=['GET'])
def get_user():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    return jsonify({'success': True, 'username': session['username']}), 200

@app.route('/api/user-details/<username>', methods=['GET'])
def user_details(username):
    """Get detailed user information"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    try:
        users = db.get_user(username)
        if not users:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        user_obj = users[0]  # get_user returns a list
        return jsonify({
            'success': True,
            'user': {
                'username': user_obj.username,
                'hash_mode': user_obj.hash_mode,
                'group_seed': user_obj.group_seed,
                'salt': user_obj.salt if user_obj.salt else None,
                'metadata': user_obj.metadata,
                'created_at': getattr(user_obj, 'created_at', None) or user_obj.metadata.get('created_at', None) if isinstance(user_obj.metadata, dict) else None
            }
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login-logs', methods=['GET'])
def get_login_logs():
    """Get login logs (admin endpoint - add authentication as needed)"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    try:
        username = request.args.get('username', None)
        limit = request.args.get('limit', 100, type=int)

        logs = db.get_login_logs(limit=limit, username=username)
        logs_data = [
            {
                'id': log.id,
                'username': log.username,
                'timestamp': log.timestamp,
                'status': log.status,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent
            }
            for log in logs
        ]
        return jsonify({'success': True, 'logs': logs_data}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def statistics():
    """Get statistics: total users, successful/failed logins today"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401

    try:
        # Get all login logs
        all_logs = db.get_login_logs(limit=10000)

        # Get today's date
        today = datetime.now().date()

        # Count statistics
        successful_logins = sum(1 for log in all_logs if log.status == 'success' and datetime.fromisoformat(log.timestamp).date() == today)
        failed_logins = sum(1 for log in all_logs if log.status == 'failed' and datetime.fromisoformat(log.timestamp).date() == today)

        # Count total users
        total_users = db.get_total_users()

        return jsonify({
            'success': True,
            'totalUsers': total_users,
            'successfulLogins': successful_logins,
            'failedLogins': failed_logins
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    print("Starting Flask server on http://0.0.0.0:5000")
    print("Open http://localhost:5000 in your browser")
    print("Database initialized at users.db")
    app.run(host='0.0.0.0', port=5000, debug=True)
