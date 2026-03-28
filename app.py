from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import secrets
import os

app = Flask(__name__)

# ── Core config ───────────────────────────────────────────────────────────────
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gaming.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── Mail config — set these as Environment Variables on Render ────────────────
app.config['MAIL_SERVER']         = os.environ.get('MAIL_SERVER',         'smtp.gmail.com')
app.config['MAIL_PORT']           = int(os.environ.get('MAIL_PORT',       '587'))
app.config['MAIL_USE_TLS']        = os.environ.get('MAIL_USE_TLS',        'true').lower() == 'true'
app.config['MAIL_USERNAME']       = os.environ.get('MAIL_USERNAME',       '')
app.config['MAIL_PASSWORD']       = os.environ.get('MAIL_PASSWORD',       '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', '')
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))

db   = SQLAlchemy(app)
mail = Mail(app)

# ═══════════════════════════ MODELS ══════════════════════════════════════════

class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    registrations = db.relationship('Registration', backref='user', lazy=True)
    reset_tokens  = db.relationship('PasswordResetToken', backref='user', lazy=True)


class Event(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    title         = db.Column(db.String(200), nullable=False)
    game          = db.Column(db.String(100), nullable=False)
    description   = db.Column(db.Text)
    event_date    = db.Column(db.DateTime, nullable=False)
    slots_total   = db.Column(db.Integer, default=16)
    entry_fee     = db.Column(db.Float,   default=0.0)
    prize_pool    = db.Column(db.String(200))
    status        = db.Column(db.String(20), default='upcoming')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    registrations = db.relationship('Registration', backref='event', lazy=True)

    @property
    def slots_filled(self):
        return Registration.query.filter_by(event_id=self.id, verified=True).count()

    @property
    def slots_available(self):
        return self.slots_total - self.slots_filled


class Registration(db.Model):
    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('user.id'),  nullable=False)
    event_id           = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    ingame_name        = db.Column(db.String(100), nullable=False)
    phone              = db.Column(db.String(20))
    payment_screenshot = db.Column(db.String(300))
    payment_method     = db.Column(db.String(50))
    verified           = db.Column(db.Boolean, default=False)
    slot_number        = db.Column(db.Integer)
    registered_at      = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token      = db.Column(db.String(120), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)

    @property
    def is_valid(self):
        return not self.used and datetime.utcnow() < self.expires_at


# ═══════════════════════════ HELPERS ═════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


def try_send_email(subject, recipients, html_body):
    """Attempt to send an email. Returns (success: bool, error: str|None)."""
    try:
        msg = Message(subject=subject, recipients=recipients)
        msg.html = html_body
        mail.send(msg)
        return True, None
    except Exception as e:
        return False, str(e)


# ═══════════════════════════ PUBLIC ROUTES ════════════════════════════════════

@app.route('/')
def index():
    events = Event.query.filter_by(status='upcoming').order_by(Event.event_date).all()
    return render_template('index.html', events=events)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email    = request.form['email'].strip().lower()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, email=email,
                    password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id']  = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    regs = Registration.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, registrations=regs)


# ── Forgot / Reset Password ───────────────────────────────────────────────────

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user  = User.query.filter_by(email=email).first()

        if user:
            # Expire any existing unused tokens for this user
            existing = PasswordResetToken.query.filter_by(user_id=user.id, used=False).all()
            for t in existing:
                t.used = True
            db.session.commit()

            # Create a fresh secure token
            token = secrets.token_urlsafe(48)
            reset = PasswordResetToken(
                user_id    = user.id,
                token      = token,
                expires_at = datetime.utcnow() + timedelta(hours=1)
            )
            db.session.add(reset)
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)

            # Always print to terminal — works even without email configured
            print("\n" + "=" * 65)
            print("  PASSWORD RESET LINK  (copy this if email is not set up)")
            print(f"  User : {user.email}")
            print(f"  Link : {reset_url}")
            print("=" * 65 + "\n")

            # Try to send the email
            sent, err = try_send_email(
                subject    = '🔑 Reset Your ADREAN Password',
                recipients = [user.email],
                html_body  = render_template('email_reset_password.html',
                                             username  = user.username,
                                             reset_url = reset_url)
            )

            if sent:
                flash('Reset link sent! Check your inbox (and spam folder).', 'success')
            else:
                print(f"[EMAIL ERROR] {err}")
                # Show the link right on the page as a fallback
                flash(
                    f'Email is not configured yet. Use this link to reset your password '
                    f'(valid for 1 hour): {reset_url}',
                    'warning'
                )
        else:
            flash('If that email is registered, a reset link has been sent.', 'info')

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset = PasswordResetToken.query.filter_by(token=token).first()

    if not reset or not reset.is_valid:
        flash('This reset link is invalid or has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm  = request.form['confirm_password']

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('reset_password', token=token))
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        reset.user.password_hash = generate_password_hash(password)
        reset.used = True
        db.session.commit()

        flash('Password reset successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ═══════════════════════════ EVENTS ══════════════════════════════════════════

@app.route('/events')
def events():
    game_filter = request.args.get('game', '')
    date_filter = request.args.get('date', '')
    query = Event.query.filter_by(status='upcoming')
    if game_filter:
        query = query.filter(Event.game.ilike(f'%{game_filter}%'))
    if date_filter:
        try:
            d = datetime.strptime(date_filter, '%Y-%m-%d')
            query = query.filter(db.func.date(Event.event_date) == d.date())
        except Exception:
            pass
    events_list = query.order_by(Event.event_date).all()
    games = db.session.query(Event.game).distinct().all()
    return render_template('events.html', events=events_list,
                           games=[g[0] for g in games],
                           game_filter=game_filter, date_filter=date_filter)


@app.route('/events/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    already_registered = False
    if 'user_id' in session:
        already_registered = Registration.query.filter_by(
            user_id=session['user_id'], event_id=event_id).first() is not None
    return render_template('event_detail.html', event=event,
                           already_registered=already_registered)


@app.route('/events/<int:event_id>/join', methods=['GET', 'POST'])
@login_required
def join_event(event_id):
    event = Event.query.get_or_404(event_id)
    if Registration.query.filter_by(user_id=session['user_id'], event_id=event_id).first():
        flash('You already registered for this event.', 'warning')
        return redirect(url_for('event_detail', event_id=event_id))
    if event.slots_available <= 0:
        flash('No slots available.', 'danger')
        return redirect(url_for('event_detail', event_id=event_id))
    if request.method == 'POST':
        reg = Registration(
            user_id            = session['user_id'],
            event_id           = event_id,
            ingame_name        = request.form['ingame_name'].strip(),
            phone              = request.form.get('phone', '').strip(),
            payment_method     = request.form.get('payment_method', ''),
            payment_screenshot = request.form.get('payment_note', '')
        )
        db.session.add(reg)
        db.session.commit()
        flash('Registration submitted! Await admin verification after payment.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('join_event.html', event=event)


# ═══════════════════════════ ADMIN ROUTES ════════════════════════════════════

@app.route('/admin')
def admin_redirect():
    return redirect(url_for('admin_login'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD, password):
            session['is_admin']       = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.', 'danger')
    return render_template('admin/login.html')


@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    total_users  = User.query.count()
    total_events = Event.query.count()
    pending      = Registration.query.filter_by(verified=False).count()
    verified     = Registration.query.filter_by(verified=True).count()
    recent_regs  = Registration.query.order_by(Registration.registered_at.desc()).limit(8).all()
    upcoming     = Event.query.filter_by(status='upcoming').order_by(Event.event_date).limit(5).all()
    return render_template('admin/dashboard.html',
                           total_users=total_users, total_events=total_events,
                           pending=pending, verified=verified,
                           recent_regs=recent_regs, upcoming=upcoming)


@app.route('/admin/events')
@admin_required
def admin_events():
    events_list = Event.query.order_by(Event.created_at.desc()).all()
    return render_template('admin/events.html', events=events_list)


@app.route('/admin/events/new', methods=['GET', 'POST'])
@admin_required
def admin_new_event():
    if request.method == 'POST':
        event = Event(
            title       = request.form['title'],
            game        = request.form['game'],
            description = request.form['description'],
            event_date  = datetime.strptime(request.form['event_date'], '%Y-%m-%dT%H:%M'),
            slots_total = int(request.form['slots_total']),
            entry_fee   = float(request.form['entry_fee']),
            prize_pool  = request.form['prize_pool'],
            status      = request.form['status']
        )
        db.session.add(event)
        db.session.commit()
        flash('Event created!', 'success')
        return redirect(url_for('admin_events'))
    return render_template('admin/event_form.html', event=None)


@app.route('/admin/events/<int:event_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if request.method == 'POST':
        event.title       = request.form['title']
        event.game        = request.form['game']
        event.description = request.form['description']
        event.event_date  = datetime.strptime(request.form['event_date'], '%Y-%m-%dT%H:%M')
        event.slots_total = int(request.form['slots_total'])
        event.entry_fee   = float(request.form['entry_fee'])
        event.prize_pool  = request.form['prize_pool']
        event.status      = request.form['status']
        db.session.commit()
        flash('Event updated!', 'success')
        return redirect(url_for('admin_events'))
    return render_template('admin/event_form.html', event=event)


@app.route('/admin/events/<int:event_id>/delete', methods=['POST'])
@admin_required
def admin_delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    Registration.query.filter_by(event_id=event_id).delete()
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted.', 'info')
    return redirect(url_for('admin_events'))


@app.route('/admin/players')
@admin_required
def admin_players():
    status = request.args.get('status', 'all')
    query  = Registration.query
    if status == 'pending':
        query = query.filter_by(verified=False)
    elif status == 'verified':
        query = query.filter_by(verified=True)
    regs = query.order_by(Registration.registered_at.desc()).all()
    return render_template('admin/players.html', registrations=regs, status=status)


@app.route('/admin/players/<int:reg_id>/verify', methods=['POST'])
@admin_required
def admin_verify(reg_id):
    reg = Registration.query.get_or_404(reg_id)
    if not reg.verified:
        used_slots = [r.slot_number for r in
                      Registration.query.filter_by(event_id=reg.event_id, verified=True).all()
                      if r.slot_number]
        slot = 1
        while slot in used_slots:
            slot += 1
        reg.verified    = True
        reg.slot_number = slot
        db.session.commit()

        sent, err = try_send_email(
            subject    = f'🎮 Slot Confirmed — {reg.event.title}',
            recipients = [reg.user.email],
            html_body  = render_template('email_confirmation.html',
                                         username    = reg.user.username,
                                         event_title = reg.event.title,
                                         slot_number = slot)
        )
        if sent:
            flash(f'Player verified & email sent (Slot #{slot}).', 'success')
        else:
            flash(f'Player verified (Slot #{slot}). Email failed — check mail config.', 'warning')
    return redirect(url_for('admin_players'))


@app.route('/admin/players/<int:reg_id>/reject', methods=['POST'])
@admin_required
def admin_reject(reg_id):
    reg = Registration.query.get_or_404(reg_id)
    db.session.delete(reg)
    db.session.commit()
    flash('Registration rejected and removed.', 'info')
    return redirect(url_for('admin_players'))


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


# ═══════════════════════════ INIT ════════════════════════════════════════════

if __name__ == '__main__':
    with app.app_context():
        db.create_all()   # creates ALL tables including PasswordResetToken
        if Event.query.count() == 0:
            sample = Event(
                title       = 'BGMI Season Opener',
                game        = 'BGMI',
                description = 'Kick off the season with our first ranked tournament. Top 3 teams win prizes!',
                event_date  = datetime(2025, 5, 10, 18, 0),
                slots_total = 16,
                entry_fee   = 100.0,
                prize_pool  = '₹5000 Prize Pool',
                status      = 'upcoming'
            )
            db.session.add(sample)
            db.session.commit()
    app.run(debug=True)