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

tentative_login = {}


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='ANALYST')
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
    token = db.Column(db.String(64), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)


def save_log(user_id, action, resource, resource_id=''):
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        resource_id=str(resource_id),
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()


def prea_multe_cereri(ip, maxim=5, interval=300):
    acum = time.time()
    if ip not in tentative_login:
        tentative_login[ip] = []
    tentative_login[ip] = [t for t in tentative_login[ip] if acum - t < interval]
    if len(tentative_login[ip]) >= maxim:
        return False
    tentative_login[ip].append(acum)
    return True


def verifica_parola(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, ""


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
        flash('Access denied', 'error')
        return redirect(url_for('profile'))
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template('audit.html', logs=logs)


@app.route('/logout', methods=['GET'])
def logout_page():
    if 'user_id' in session:
        save_log(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login_page'))


@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'ANALYST')

    ok, mesaj = verifica_parola(password)
    if not ok:
        if request.is_json:
            return jsonify({'error': mesaj}), 400
        flash(mesaj, 'error')
        return redirect(url_for('register_page'))

    existent = User.query.filter_by(email=email).first()
    if existent:
        if request.is_json:
            return jsonify({'error': 'Email already exists'}), 400
        flash('Email already exists', 'error')
        return redirect(url_for('register_page'))

    parola_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(email=email, password_hash=parola_hash, role=role)
    db.session.add(user)
    db.session.commit()
    save_log(user.id, 'REGISTER', 'auth')

    if request.is_json:
        return jsonify({'message': 'User created successfully'}), 201
    flash('Account created! You can now log in.', 'success')
    return redirect(url_for('login_page'))


@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if not prea_multe_cereri(ip):
        if request.is_json:
            return jsonify({'error': 'Too many attempts. Try again later.'}), 429
        flash('Too many login attempts. Please wait 5 minutes.', 'error')
        return redirect(url_for('login_page'))

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    email=data.get('email', '').strip().lower()
    password = data.get('password', '')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        save_log(None, 'LOGIN_FAIL', 'auth')
        time.sleep(0.5)
        if request.is_json:
            return jsonify({'error': 'Invalid credentials'}), 401
        flash('Invalid credentials', 'error')
        return redirect(url_for('login_page'))

    if user.locked:
        if request.is_json:
            return jsonify({'error': 'Account locked'}), 403
        flash('Your account is locked.', 'error')
        return redirect(url_for('login_page'))

    session.clear()
    session.permanent = True
    session['user_id'] = user.id
    session['email'] = user.email
    session['role'] = user.role
    save_log(user.id, 'LOGIN', 'auth')

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
        flash('If that email exists, you will receive reset instructions.', 'success')
        return redirect(url_for('forgot_password_page'))

    token= ecrets.token_urlsafe(32)

    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
    db.session.commit()

    reset_token = PasswordResetToken(user_id=user.id, token=token)
    db.session.add(reset_token)
    db.session.commit()

    if request.is_json:
        return jsonify({'message': 'If email exists, a reset link was sent', 'token': token}), 200
    flash(f'Reset token: {token}', 'success')
    return redirect(url_for('reset_password_page', token=token))


@app.route('/reset-password', methods=['POST'])
def reset_password():
    if request.is_json:
        data = request.get_json()
    else:

        data =request.form

    token = data.get('token', '')
    parola_noua = data.get('new_password', '')

    reset = PasswordResetToken.query.filter_by(token=token, used=False).first()
    if not reset:
        if request.is_json:
            return jsonify({'error': 'Invalid or expired token'}), 400
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('login_page'))

    if datetime.utcnow() - reset.created_at > timedelta(minutes=15):
        reset.used = True
        db.session.commit()
        if request.is_json: 

            return jsonify({'error': 'Token expired'}), 400
        flash('Token has expired. Please try again.', 'error')
        return redirect(url_for('login_page'))

    ok, mesaj = verifica_parola(parola_noua)
    if not ok:
        if request.is_json:
            return jsonify({'error': mesaj}), 400
        flash(mesaj, 'error')
        return redirect(url_for('reset_password_page',token=token))

    user = User.query.get(reset.user_id)
    user.password_hash= bcrypt.hashpw(parola_noua.encode(), bcrypt.gensalt()).decode()
    reset.used =True
    db.session.commit()
    save_log(user.id, 'RESET_PASSWORD', 'auth')

    if request.is_json:
        return jsonify({'message': 'Password reset successful'}), 200
    flash('Password changed successfully!', 'success')
    return redirect(url_for('login_page'))


@app.route('/tickets',methods=['POST'])
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
    save_log(session['user_id'], 'CREATE_TICKET', 'ticket', ticket.id)

    if request.is_json:
        return jsonify({'message': 'Ticket created', 'id': ticket.id}), 201
    flash('Ticket added successfully!', 'success')
    return redirect(url_for('tickets_page'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5001)