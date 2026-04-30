from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = "secret123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://antonia:antonia123@localhost/authxdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PasswordResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    token = db.Column(db.String(64))
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

# ─── GET ROUTES (HTML) ────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    token = request.args.get('token', '')
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/tickets', methods=['GET'])
def tickets_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    tickets = Ticket.query.filter_by(owner_id=session['user_id']).all()
    return render_template('tickets.html', tickets=tickets)

@app.route('/audit', methods=['GET'])
def audit_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') != 'MANAGER':
        flash('Acces interzis', 'error')
        return redirect(url_for('profile'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('audit.html', logs=logs)

@app.route('/logout', methods=['GET'])
def logout_page():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    flash('Ai fost delogat cu succes.', 'success')
    return redirect(url_for('login_page'))

# ─── POST ROUTES (API) ────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'ANALYST')
    password_hash = hashlib.md5(password.encode()).hexdigest()
    existing = User.query.filter_by(email=email).first()
    if existing:
        if request.is_json:
            return jsonify({'error': 'Email already exists'}), 400
        flash('Email-ul există deja!', 'error')
        return redirect(url_for('register_page'))
    user = User(email=email, password_hash=password_hash, role=role)
    db.session.add(user)
    db.session.commit()
    log_action(user.id, 'REGISTER', 'auth')
    if request.is_json:
        return jsonify({'message': 'User created successfully'}), 201
    flash('Cont creat cu succes! Autentifică-te.', 'success')
    return redirect(url_for('login_page'))

@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if not user:
        if request.is_json:
            return jsonify({'error': 'User not found'}), 404
        flash('User not found', 'error')
        return redirect(url_for('login_page'))
    password_hash = hashlib.md5(password.encode()).hexdigest()
    if user.password_hash != password_hash:
        log_action(None, 'LOGIN_FAIL', 'auth')
        if request.is_json:
            return jsonify({'error': 'Wrong password'}), 401
        flash('Wrong password', 'error')
        return redirect(url_for('login_page'))
    session['user_id'] = user.id
    session['email'] = user.email
    session['role'] = user.role
    log_action(user.id, 'LOGIN', 'auth')
    if request.is_json:
        return jsonify({'message': 'Login successful', 'role': user.role}), 200
    return redirect(url_for('profile'))

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        if request.is_json:
            return jsonify({'error': 'Email not found'}), 404
        flash('Email-ul nu există.', 'error')
        return redirect(url_for('forgot_password_page'))
    token = str(user.id) + "reset"
    reset_token = PasswordResetToken(user_id=user.id, token=token)
    db.session.add(reset_token)
    db.session.commit()
    if request.is_json:
        return jsonify({'message': 'Reset token generated', 'token': token}), 200
    flash(f'Token de resetare: {token} (în producție se trimite pe email)', 'success')
    return redirect(url_for('reset_password_page', token=token))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    token = data.get('token')
    new_password = data.get('new_password')
    reset = PasswordResetToken.query.filter_by(token=token).first()
    if not reset:
        if request.is_json:
            return jsonify({'error': 'Invalid token'}), 400
        flash('Token invalid!', 'error')
        return redirect(url_for('login_page'))
    user = User.query.get(reset.user_id)
    user.password_hash = hashlib.md5(new_password.encode()).hexdigest()
    db.session.commit()
    log_action(user.id, 'RESET_PASSWORD', 'auth')
    if request.is_json:
        return jsonify({'message': 'Password reset successful'}), 200
    flash('Parola a fost resetată cu succes!', 'success')
    return redirect(url_for('login_page'))

@app.route('/tickets', methods=['POST'])
def create_ticket():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    ticket = Ticket(
        title=data.get('title'),
        description=data.get('description'),
        severity=data.get('severity', 'LOW'),
        owner_id=session['user_id']
    )
    db.session.add(ticket)
    db.session.commit()
    log_action(session['user_id'], 'CREATE_TICKET', 'ticket', ticket.id)
    if request.is_json:
        return jsonify({'message': 'Ticket created', 'id': ticket.id}), 201
    flash('Ticket creat cu succes!', 'success')
    return redirect(url_for('tickets_page'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
