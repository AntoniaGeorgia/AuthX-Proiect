from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import bcrypt
import secrets
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://antonia:antonia123@localhost/authxdb_secure'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
login_attempts = {}

class User(db.Model):
    __tablename__='users'
    id=db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(120), unique=True, nullable=False)
    password_hash=db.Column(db.String(256), nullable=False)
    role=db.Column(db.String(20), default='ANALYST')
    created_at=db.Column(db.DateTime, default=datetime.utcnow)
    locked=db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    __tablename__='tickets'
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(200),nullable=False)
    description=db.Column(db.Text)
    severity= db.Column(db.String(10),default='LOW')
    status =db.Column(db.String(20),default='OPEN')
    owner_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime,default=datetime.utcnow)
    updated_at = db.Column(db.DateTime,default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ ='audit_logs'
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('users.id'),nullable=True)
    action=db.Column(db.String(50))
    resource =db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime,default=datetime.utcnow)

class PasswordResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    token =db.Column(db.String(64),unique=True)
    created_at = db.Column(db.DateTime,default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

def log_action(user_id, action, resource,resource_id=''):
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=str(resource_id),
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

def check_rate_limit(ip, max_attempts=5, window=300):
    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip] =[t for t in login_attempts[ip] if now - t < window]
    if len(login_attempts[ip]) >= max_attempts:
        return False
    login_attempts[ip].append(now)
    return True

def validate_password(password):
    if len(password) < 8:
        return False, "Parola trebuie sa aiba minim 8 caractere"
    if not any(c.isupper() for c in password):
        return False, "Parola trebuie sa contina celputin o litera mare"
    if not any(c.isdigit() for c in password):
        return False, "Parola trebuie sa contina cel putin o cifra"
    return True, ""

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('login_page'))

@app.route('/login',methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register',methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/forgot-password',methods=['GET'])
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/reset-password',methods=['GET'])
def reset_password_page():
    token = request.args.get('token', '')
    return render_template('reset_password.html', token=token)

@app.route('/profile',methods=['GET'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/tickets',methods=['GET'])
def tickets_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    tickets = Ticket.query.filter_by(owner_id=session['user_id']).all()
    return render_template('tickets.html', tickets=tickets)

@app.route('/audit',methods=['GET'])
def audit_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if session.get('role') != 'MANAGER':
        flash('Acces interzis', 'error')
        return redirect(url_for('profile'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('audit.html', logs=logs)

@app.route('/logout',methods=['GET'])
def logout_page():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    flash('Ai fost delogat.', 'success')
    return redirect(url_for('login_page'))

@app.route('/register',methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'ANALYST')
    valid, msg = validate_password(password)
    if not valid:
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('register_page'))
    existing = User.query.filter_by(email=email).first()
    if existing:
        if request.is_json:
            return jsonify({'error': 'Email already exists'}), 400
        flash('Email-ul exista deja', 'error')
        return redirect(url_for('register_page'))
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(email=email, password_hash=password_hash, role=role)
    db.session.add(user)
    db.session.commit()
    log_action(user.id, 'REGISTER', 'auth')
    if request.is_json:
        return jsonify({'message': 'User created successfully'}), 201
    flash('Cont creat! Autentifica-te.', 'success')
    return redirect(url_for('login_page'))

@app.route('/login',methods=['POST'])
def login():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        if request.is_json:
            return jsonify({'error': 'Too many attempts. Try again later.'}), 429
        flash('Prea multe incercari. Asteptati 5 minute.', 'error')
        return redirect(url_for('login_page'))
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        log_action(None, 'LOGIN_FAIL', 'auth')
        time.sleep(0.5)
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        flash('Invalid credentials', 'error')
        return redirect(url_for('login_page'))
    if user.locked:
        if request.is_json:
            return jsonify({'error': 'Account locked'}), 403
        flash('Contul este blocat.', 'error')
        return redirect(url_for('login_page'))
    session.clear()
    session.permanent = True
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
    email = data.get('email', '').strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        if request.is_json:
            return jsonify({'message': 'If email exists, a reset link was sent'}), 200
        flash('Daca emailul exista, vei primi instructiuni de resetare.', 'success')
        return redirect(url_for('forgot_password_page'))
    token = secrets.token_urlsafe(32)
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
    db.session.commit()
    reset_token = PasswordResetToken(user_id=user.id, token=token)
    db.session.add(reset_token)
    db.session.commit()
    if request.is_json:
        return jsonify({'message': 'If email exists, a reset link was sent', 'token': token}), 200
    flash(f'Token: {token}', 'success')
    return redirect(url_for('reset_password_page', token=token))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    token = data.get('token', '')
    new_password = data.get('new_password', '')
    reset = PasswordResetToken.query.filter_by(token=token, used=False).first()
    if not reset:
        if request.is_json:
            return jsonify({'error': 'Invalid or expired token'}), 400
        flash('Token invalid sau expirat.', 'error')
        return redirect(url_for('login_page'))
    if datetime.utcnow() - reset.created_at > timedelta(minutes=15):
        reset.used = True
        db.session.commit()
        if request.is_json:
            return jsonify({'error': 'Token expired'}), 400
        flash('Token expirat.', 'error')
        return redirect(url_for('login_page'))
    valid, msg = validate_password(new_password)
    if not valid:
        if request.is_json:
            return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('reset_password_page', token=token))
    user = User.query.get(reset.user_id)
    user.password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    reset.used = True
    db.session.commit()
    log_action(user.id, 'RESET_PASSWORD', 'auth')
    if request.is_json:
        return jsonify({'message': 'Password reset successful'}), 200
    flash('Parola resetata cu succes!', 'success')
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
    flash('Ticket creat!', 'success')
    return redirect(url_for('tickets_page'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5001)
