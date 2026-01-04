import os
import sys
import time
import json
import pyotp
import qrcode
import base64
import secrets
import logging

from io import BytesIO
from datetime import timedelta, datetime
from flask import Flask, render_template, request, jsonify, redirect, session, url_for

from common import ServerStatus


# Ensure src is on path so imports work when running from repo root
sys.path.insert(0, os.path.dirname(__file__))


CONFIG_PATH = os.path.join(os.path.dirname(__file__), './config.json')
with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.load(f)

# CAPTCHA_TOKENS = {
#     "<username1>": <captcha_token1>,
#     "<username2>": <captcha_token2>,
#     ...
# }
CAPTCHA_TOKENS = {}


# this app only supports these protection options:
# CAPTCHA_THRESHOLD 
# LOCKOUT_THRESHOLD
# RATE_LIMIT_ATTEMPTS
# LOCKOUT_THRESHOLD + RATE_LIMIT_ATTEMPTS (Make sure LOCKOUT_THRESHOLD > RATE_LIMIT_ATTEMPTS)
# to turn on the protection option please modify the config.json file filed accordingly 

LOCKOUT_THRESHOLD = CONFIG.get('LOCKOUT_THRESHOLD', 5)
RATE_LIMIT_ATTEMPTS = CONFIG.get('RATE_LIMIT_ATTEMPTS', 3)
RATE_LIMIT_LOCK_SEC = CONFIG.get('RATE_LIMIT_LOCK_SEC', 120)
RATE_LIMIT_ACTIVATED = CONFIG.get('RATE_LIMIT_ACTIVATED', False)
LOCKOUT_ACTIVATED = CONFIG.get('LOCKOUT_ACTIVATED', False)
CAPTCHA_ACTIVATED = CONFIG.get('CAPTCHA_ACTIVATED', False)
CAPTCHA_THRESHOLD = CONFIG.get('CAPTCHA_THRESHOLD', 5)

# user_login_attempts = {
#     "<username>": {
#         'failed': <int>,        # consecutive number of failed attemps
#         "locked_until": <float> # timestamp
#         'locked_forever': <BOOL>, # flag to indicate if existing username is locked
#         'rate_limit_failed': <INT> # consecutive failed attemps to count rate limit
#     },
#     ...
# }
user_login_attempts = {}

from Database import DB

# Set up login attempt logger
login_logger = logging.getLogger('login_attempts')
if not login_logger.handlers:
    handler = logging.FileHandler('attempts.log', encoding='utf-8')
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    login_logger.addHandler(handler)
    login_logger.setLevel(logging.INFO)


def get_or_create_captcha_token(username):
    """return a new or existing captcha token for a specific username"""
    token = CAPTCHA_TOKENS.get(username)
    if not token:
        token = secrets.token_hex(16)
        CAPTCHA_TOKENS[username] = token
    return token

def log_login_attempt_json(username, group_seed, hash_mode, protection_flags, result, latency_ms):
    """Log a login attempt with all required fields as JSON."""
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'username': username,
        'group_seed': str(group_seed),
        'hash_mode': hash_mode,
        'protection_flags': protection_flags,
        'result': result,
        'latency_ms': str(latency_ms)
    }
    login_logger.info(json.dumps(log_data, ensure_ascii=False))

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
    # verify if user has passed totp if he required to do so
    # prevent url hopping between dashboard and login
    users = db.get_user(session['username'])
    user_record = users[0] if users else None
    totp_secret = user_record.totp if user_record and hasattr(user_record, 'totp') else ''
    if totp_secret and not session.get('totp_verified'):
                return redirect(url_for('totp_verify_page'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/totp-verify')
def totp_verify_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    
    users = db.get_user(session['username'])
    user_record = users[0] if users else None
    totp_secret = user_record.totp if user_record and hasattr(user_record, 'totp') else ''
    if not totp_secret:
        return redirect(url_for('dashboard'))
    return render_template('login_totp.html', username=session['username'])

@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        hash_mode = data.get('hash_mode', 'bcrypt')  # default to bcrypt
        totp = data.get('use_totp', False)  # default to no totp
        use_pepper = data.get('use_pepper', False)

        if not username or len(username) < 3:
            return jsonify({'success': False, 'message': 'Username must be at least 3 characters'}), ServerStatus.BAD_REQUEST.value

        if not password or len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), ServerStatus.BAD_REQUEST.value

        # Check if user exists using database
        if db.user_exists(username):
            return jsonify({'success': False, 'message': 'Username already exists'}), ServerStatus.CONFLICT.value

        totp_secret = ''
        if totp:
            totp_secret = pyotp.random_base32()

        # If TOTP requested, create otpauth URI and QR code to return to client
        qr_data_uri = None
        otpauth_uri = None
        if totp_secret:
            try:
                totp_obj = pyotp.TOTP(totp_secret)
                otpauth_uri = totp_obj.provisioning_uri(name=username, issuer_name="Cyberspace Security Lab")
                # generate QR image and encode as data URI
                qr_img = qrcode.make(otpauth_uri)
                buf = BytesIO()
                qr_img.save(buf, format='PNG')
                buf.seek(0)
                qr_b64 = base64.b64encode(buf.read()).decode('ascii')
                qr_data_uri = f"data:image/png;base64,{qr_b64}"
            except Exception as e:
                print(f"Failed to generate QR code: {e}")

        # Register user in database with hashing
        try:
            db.register(username, password, hash_mode, totp_secret, use_pepper)
        except Exception as e:
            # if DB raised IntegrityError it bubbles up - return conflict
            return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value

        update_json_file(username, totp_secret)

        return jsonify({
            'success': True,
            'message': 'Registration successful. Please login.',
            'username': username,
            'totp_secret': totp_secret if totp else None,
            'otpauth_uri': otpauth_uri,
            'qr_code': qr_data_uri
        }), ServerStatus.CREATED.value

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value

def update_json_file(username, totp_secret):
    """updates users.json file with relavent username and their totp secret (or '' if not available)"""
    json_path = os.path.join(os.path.dirname(__file__), 'users.json')

    try:
        if not os.path.exists(json_path):
            users_json = {"group_seed": 524392612, "users": []}
        else:
            with open(json_path, 'r', encoding='utf-8') as f:
                users_json = json.load(f)
        users_json["users"].append({
            "username": username,
            "totp_secret": totp_secret
        })
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(users_json, f, ensure_ascii=False, indent=4)

    except Exception as e:
        print(f"Failed to update users.json file: {e}")

@app.route('/api/login', methods=['POST'])
def api_login():
    login_start = time.time()
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        captcha_token = data.get('captcha_token', '')


        # Get client info for logging
        now = time.time()
        latency_ms = int((now - login_start) * 1000)
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Get user record to extract hash_mode
        users = db.get_user(username)
        user_exists = bool(users)
        user_record = users[0] if users else None
        hash_mode = user_record.hash_mode if user_record else ''
        
        # if no usernmae or no password was provided in the request
        if not username or not password:
            latency_ms = int((time.time() - login_start) * 1000)
            log_login_attempt_json(username or 'unknown', db.group_seed, '', '', 'failed', latency_ms)
            db.log_login_attempt(username or 'unknown', 'failed', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'Username and password required'}), ServerStatus.BAD_REQUEST.value
        
        # this check prevents locking a username that does not exist
        if not user_exists:
            log_login_attempt_json(username, db.group_seed, '', '', 'failed', latency_ms)
            db.log_login_attempt(username, 'failed', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'Invalid username or password'}), ServerStatus.UNAUTHORIZED.value

        user_info = user_login_attempts.get(username, {
            'failed': 0,
            'locked_until': 0,
            'locked_forever': False,
            'rate_limit_failed': 0,
        })
        print(user_info['failed'])
        print(user_info['rate_limit_failed'])
        print(RATE_LIMIT_ACTIVATED)
        # User Locked forever check
        if user_info.get('locked_forever', False):
            log_login_attempt_json(username, db.group_seed, '', 'lockout', 'permanent lockout', latency_ms)
            db.log_login_attempt(username, 'permanent lockout', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'This Account is permanently locked. Please contact admin.'}), ServerStatus.PERMANENT_LOCKOUT.value

        # CAPTCHA SECTION
        if user_info['failed'] >= CAPTCHA_THRESHOLD - 1 and CAPTCHA_ACTIVATED:
            # check if captcha token was sent by the frontend/user
            token_needed = CAPTCHA_TOKENS.get(username)
            if captcha_token:
                if captcha_token == token_needed:
                    # if sent token was right
                    user_info['failed'] = 0
                    if username in CAPTCHA_TOKENS:
                        del CAPTCHA_TOKENS[username]
                    # afterwards the regular credentials check
                else:
                    log_login_attempt_json(username, db.group_seed, '', 'Captcha', 'Captcha required', latency_ms)
                    db.log_login_attempt(username, 'Captcha required', client_ip, user_agent)
                    return jsonify({'success': False, 'message': 'Invalid CAPTCHA token'}), ServerStatus.UNAUTHORIZED.value
            else:
                # if no token exists for <username>, create a new one
                if not token_needed:
                    token_needed = secrets.token_hex(16)
                    CAPTCHA_TOKENS[username] = token_needed
                log_login_attempt_json(username, db.group_seed, '', 'Captcha', 'Captcha required', latency_ms)
                db.log_login_attempt(username, 'Captcha required', client_ip, user_agent)
                return jsonify({'captcha_required': True, 'captcha_token': token_needed,
                                 'message':'exceeded failed attemps captcha thresholds, please provide captcha token'}), ServerStatus.TOO_MANY_REQUESTS.value

        # Rate-Limit validation
        locked_until = user_info.get('locked_until',0)
        seconds_left = int(locked_until - time.time())
        if seconds_left > 0:
            log_login_attempt_json(username, db.group_seed, '', 'rate-limit', 'rate limit lockout', latency_ms)
            db.log_login_attempt(username, 'rate limit lockout', client_ip, user_agent)
            return jsonify({'success': False, 'message': f'This account is locked for {seconds_left} seconds'}), ServerStatus.TOO_MANY_REQUESTS.value
            

        user_info = user_login_attempts.get(username, {
            'failed': 0,
            'locked_until': 0,
            'locked_forever': False,
            'rate_limit_failed': 0,
        })

        # User Locked forever check
        if user_info.get('locked_forever', False):
            log_login_attempt_json(username, db.group_seed, '', 'lockout', 'permanent lockout', latency_ms)
            db.log_login_attempt(username, 'permanent lockout', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'This Account is permanently locked. Please contact admin.'}), ServerStatus.PERMANENT_LOCKOUT.value

        # Rate-Limit validation
        locked_until = user_info.get('locked_until',0)
        seconds_left = int(locked_until - time.time())
        if seconds_left > 0:
            log_login_attempt_json(username, db.group_seed, '', 'rate-limit', 'rate limit lockout', latency_ms)
            db.log_login_attempt(username, 'rate limit lockout', client_ip, user_agent)
            return jsonify({'success': False, 'message': f'This account is locked for {seconds_left} seconds'}), ServerStatus.TOO_MANY_REQUESTS.value
            

        # Verify login using database
        if not db.login(username, password):
            user_info['failed'] += 1
            user_info['rate_limit_failed'] += 1
            # lockout check
            if user_info['failed'] >= LOCKOUT_THRESHOLD and LOCKOUT_ACTIVATED:
                user_info['locked_forever'] = True
                latency_ms = int((time.time() - login_start) * 1000)
                log_login_attempt_json(username, db.group_seed, hash_mode, 'permanent lockout', 'permanent lockout', latency_ms)
                db.log_login_attempt(username, 'permanent lockout', client_ip, user_agent)
                return jsonify({'success': False, 'message': 'This Account is permanently locked. Please contact admin.'}), ServerStatus.PERMANENT_LOCKOUT.value

            # rate limit check
            if user_info['rate_limit_failed'] >= RATE_LIMIT_ATTEMPTS and RATE_LIMIT_ACTIVATED :
                print(user_info['rate_limit_failed'])
                user_info['locked_until'] = now + RATE_LIMIT_LOCK_SEC
                user_info['rate_limit_failed'] = 0
                locked_until = user_info.get('locked_until',0)
                seconds_left = int(locked_until - time.time())
            
                latency_ms = int((time.time() - login_start) * 1000)
                log_login_attempt_json(username, db.group_seed, hash_mode, 'rate limit lockout', 'rate limit lockout', latency_ms)
                db.log_login_attempt(username, 'rate limit lockout', client_ip, user_agent)
                if  user_info['failed'] != LOCKOUT_THRESHOLD:
                    return jsonify({'success': False, 'message': f'This account is locked for {seconds_left} seconds'}), ServerStatus.TOO_MANY_REQUESTS.value
            
            user_login_attempts[username] = user_info
            # if no lockout is applicable in this login attempt
            latency_ms = int((time.time() - login_start) * 1000)
            log_login_attempt_json(username, db.group_seed, hash_mode, '', 'failed', latency_ms)
            db.log_login_attempt(username, 'failed', client_ip, user_agent)
            return jsonify({'success': False, 'message': 'Invalid username or password'}), ServerStatus.UNAUTHORIZED.value

        # Login successful
        session['username'] = username
        session.permanent = True

        # Login successful - reset state for lockout and rate limit
        user_login_attempts[username] = {
            'failed': 0,
            'locked_until': 0,
            'locked_forever': False,
            'rate_limit_failed': 0,

        }

        # Login successful - reset state for lockout and rate limit
        user_login_attempts[username] = {
            'failed': 0,
            'locked_until': 0,
            'locked_forever': False,
            'rate_limit_failed': 0,

        }

        # get user record from DB to determine if TOTP is required
        totp_secret = user_record.totp if user_record and hasattr(user_record, 'totp') else ''

        # If user has TOTP enabled, mark as not yet verified and request TOTP
        if totp_secret:
            session['totp_verified'] = False
            latency_ms = int((time.time() - login_start) * 1000)
            log_login_attempt_json(username, db.group_seed, hash_mode, 'totp_required', 'requires_totp', latency_ms)
            db.log_login_attempt(username, 'requires totp', client_ip, user_agent)
            return jsonify({
                'success': True,
                'message': 'TOTP required',
                'username': username,
                'redirect': '/totp-verify'
            }), ServerStatus.OK.value

        # No TOTP configured — mark verified and finish login
        session['totp_verified'] = True
        latency_ms = int((time.time() - login_start) * 1000)
        log_login_attempt_json(username, db.group_seed, hash_mode, '', 'success', latency_ms)
        db.log_login_attempt(username, 'success', client_ip, user_agent)

        return jsonify({'success': True, 'message': 'Login successful', 'username': username, 'redirect': '/dashboard'}), ServerStatus.OK.value

    except Exception as e:
        latency_ms = int((time.time() - login_start) * 1000)
        log_login_attempt_json('', db.group_seed, '', '', f'error: {str(e)[:50]}', latency_ms)
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value


@app.route('/api/verify-totp', methods=['POST'])
def verify_totp():
    try:
        # verify user has passed the log in
        if 'username' not in session:
            return jsonify({'success': False, 'message': 'Not authenticated'}), ServerStatus.UNAUTHORIZED.value
        
        # Get client info from log in
        data = request.get_json()
        totp_code = data.get('totp', '').strip()
        username = session['username']
        
        # get user info from DB
        users = db.get_user(username)
        user_records = users[0]

        # check if user has TOTP
        if not user_records or not hasattr(user_records, 'totp'):
            return jsonify({'success': False, 'message': 'User TOTP secret not found'}), ServerStatus.BAD_REQUEST.value
        
        # get the TOTP value
        totp_secret = user_records.totp or ''
        if not totp_secret:
            return jsonify({'success': False, 'message': 'User does not have TOTP enabled'}), ServerStatus.BAD_REQUEST.value

        # TOTP verification
        totp_verifier = pyotp.TOTP(totp_secret)
        if totp_verifier.verify(totp_code, valid_window=1):
            session['totp_verified'] = True

            # update login logs
            client_ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', 'Unknown')
            db.log_login_attempt(username, 'success', client_ip, user_agent)
            
            return jsonify({'success': True, 'message': 'TOTP verified! Redirecting to dashboard page'}), ServerStatus.OK.value
        
        else:
            return jsonify({'success': False, 'message': 'Invalid TOTP code. Please check and try again.'}), ServerStatus.UNAUTHORIZED.value
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value


@app.route('/api/logout', methods=['POST'])
def api_logout():
    username = session.get('username', 'unknown')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    db.log_login_attempt(username, 'logout', client_ip, user_agent)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'}), ServerStatus.OK.value

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'message': 'Server is running'}), ServerStatus.OK.value

@app.route('/api/user', methods=['GET'])
def get_user():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), ServerStatus.UNAUTHORIZED.value
    return jsonify({'success': True, 'username': session['username']}), ServerStatus.OK.value

@app.route('/api/user-details/<username>', methods=['GET'])
def user_details(username):
    """Get detailed user information"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), ServerStatus.UNAUTHORIZED.value

    try:
        users = db.get_user(username)
        if not users:
            return jsonify({'success': False, 'message': 'User not found'}), ServerStatus.NOT_FOUND.value

        user_obj = users[0]  # get_user returns a list
        return jsonify({
            'success': True,
            'user': {
                'username': user_obj.username,
                'hash_mode': user_obj.hash_mode,
                'group_seed': user_obj.group_seed,
                'salt': user_obj.salt.decode() if isinstance(user_obj.salt, bytes) else user_obj.salt if user_obj.salt else None,
                'metadata': user_obj.metadata,
                'created_at': getattr(user_obj, 'created_at', None) or user_obj.metadata.get('created_at', None) if isinstance(user_obj.metadata, dict) else None,
                'totp': user_obj.totp,
                'pepper': user_obj.pepper
            }
        }), ServerStatus.OK.value
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value

@app.route('/api/login-logs', methods=['GET'])
def get_login_logs():
    """Get login logs (admin endpoint - add authentication as needed)"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), ServerStatus.UNAUTHORIZED.value

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
        return jsonify({'success': True, 'logs': logs_data}), ServerStatus.OK.value
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value

@app.route('/api/statistics', methods=['GET'])
def statistics():
    """Get statistics: total users, successful/failed logins today"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), ServerStatus.UNAUTHORIZED.value

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
        }), ServerStatus.OK.value
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), ServerStatus.INTERNAL_ERROR.value


@app.route('/admin/get_captcha_token')
def get_captcha_token():
    group_seed = request.args.get('group_seed', '')
    username = request.args.get('username', '')
    if group_seed != str(db.group_seed):
        return jsonify({"error": "Invalid group_seed"}), ServerStatus.UNAUTHORIZED.value
    token = CAPTCHA_TOKENS.get(username)
    if not token:
        token = secrets.token_hex(16)
        CAPTCHA_TOKENS[username] = token
    return jsonify({"captcha_token": token}), ServerStatus.OK.value

@app.errorhandler(ServerStatus.NOT_FOUND.value)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), ServerStatus.NOT_FOUND.value

@app.errorhandler(ServerStatus.INTERNAL_ERROR.value)
def server_error(error):
    return jsonify({'error': 'Server error'}), ServerStatus.INTERNAL_ERROR.value


def create_app():
    print("Starting Flask server on http://0.0.0.0:5000")
    print("Open http://localhost:5000 in your browser")
    print("Database initialized at users.db")
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == '__main__':
    create_app()
