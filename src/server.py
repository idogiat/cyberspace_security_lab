from flask import Flask, render_template, request, jsonify, redirect, session, url_for
import json
from datetime import timedelta

app = Flask(__name__, template_folder='templates')
app.secret_key = 'your-secret-key-change-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Simple in-memory user storage
users = {}
sessions_store = {}

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
        
        if not username or len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), 400
        
        if not password or len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        if username in users:
            return jsonify({'success': False, 'message': 'Username already exists'}), 409
        
        users[username] = {'password': password}
        return jsonify({'success': True, 'message': 'Registration successful. Please login.', 'username': username}), 201
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        if username not in users:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
        
        if users[username]['password'] != password:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
        
        session['username'] = username
        session.permanent = True
        
        return jsonify({'success': True, 'message': 'Login successful', 'username': username, 'redirect': '/dashboard'}), 200
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
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

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    print("Starting Flask server on http://0.0.0.0:5000")
    print("Open http://localhost:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=True)