from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from collections import defaultdict
import bcrypt
import secrets
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://antonia:antonia123@localhost/authxdb_secure'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)

login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
BLOCK_SECONDS = 300

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='USER')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    locked = db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), default='LOW')
    status = db.Column(db.String(20), default='OPEN')
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50))
    resource = db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

class PasswordResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    token = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

def log_action(user_id, action, resource, resource_id=''):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=str(resource_id),
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def is_rate_limited(ip):
    now = time.time()
    attempts = login_attempts[ip]
    attempts = [t for t in attempts if now - t < BLOCK_SECONDS]
    login_attempts[ip] = attempts
    return len(attempts) >= MAX_ATTEMPTS

def record_attempt(ip):
    login_attempts[ip].append(time.time())

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Invalid input'}), 400
    if not validate_password(password):
        return jsonify({'error': 'Password must be at least 8 characters, contain uppercase and a digit'}), 400
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({'error': 'Registration failed'}), 400
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    log_action(user.id, 'REGISTER', 'auth')
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if is_rate_limited(ip):
        log_action(None, 'LOGIN_BLOCKED', 'auth')
        return jsonify({'error': 'Too many attempts. Try again later.'}), 429
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    time.sleep(0.5)
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        record_attempt(ip)
        log_action(None, 'LOGIN_FAIL', 'auth')
        return jsonify({'error': 'Invalid credentials'}), 401
    session.clear()
    session['user_id'] = user.id
    session['email'] = user.email
    session['role'] = user.role
    log_action(user.id, 'LOGIN', 'auth')
    return jsonify({'message': 'Login successful', 'role': user.role}), 200

@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        token = secrets.token_urlsafe(32)
        reset_token = PasswordResetToken(user_id=user.id, token=token)
        db.session.add(reset_token)
        db.session.commit()
    return jsonify({'message': 'If the email exists, a reset link was sent'}), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    if not validate_password(new_password):
        return jsonify({'error': 'Password too weak'}), 400
    reset = PasswordResetToken.query.filter_by(token=token, used=False).first()
    if not reset:
        return jsonify({'error': 'Invalid or expired token'}), 400
    expires_at = reset.created_at + timedelta(minutes=15)
    if datetime.utcnow() > expires_at:
        return jsonify({'error': 'Token expired'}), 400
    user = User.query.get(reset.user_id)
    user.password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    reset.used = True
    db.session.commit()
    log_action(user.id, 'RESET_PASSWORD', 'auth')
    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'email': session['email'], 'role': session['role']}), 200

@app.route('/tickets', methods=['GET'])
def get_tickets():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    tickets = Ticket.query.filter_by(owner_id=session['user_id']).all()
    return jsonify([{
        'id': t.id, 'title': t.title,
        'severity': t.severity, 'status': t.status,
        'owner_id': t.owner_id
    } for t in tickets]), 200

@app.route('/tickets', methods=['POST'])
def create_ticket():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    ticket = Ticket(
        title=data.get('title'),
        description=data.get('description'),
        severity=data.get('severity', 'LOW'),
        owner_id=session['user_id']
    )
    db.session.add(ticket)
    db.session.commit()
    log_action(session['user_id'], 'CREATE_TICKET', 'ticket', ticket.id)
    return jsonify({'message': 'Ticket created', 'id': ticket.id}), 201

@app.route('/audit', methods=['GET'])
def get_audit():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if session.get('role') != 'MANAGER':
        return jsonify({'error': 'Forbidden'}), 403
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        'user_id': l.user_id, 'action': l.action,
        'resource': l.resource, 'timestamp': str(l.timestamp),
        'ip': l.ip_address
    } for l in logs]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5001)
