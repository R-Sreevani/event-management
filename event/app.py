from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# ✅ Inject current datetime object into all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ----------------- Models -----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(10))  # 'admin' or 'student'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    venue = db.Column(db.String(100), nullable=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')

# ----------------- Routes -----------------
@app.route('/')
def index():
    events = Event.query.all()
    return render_template('index.html', events=events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        if role == 'admin' and User.query.filter_by(role='admin').first():
            return "⚠️ Admin already exists. You can only register as a student."

        if User.query.filter_by(email=email).first():
            return "⚠️ User already exists with this email."

        user = User(name=name, email=email, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard'))

        return "❌ Invalid email or password"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))

    user_id = session['user_id']
    events = Event.query.all()
    registered_event_ids = [reg.event_id for reg in Registration.query.filter_by(user_id=user_id).all()]
    return render_template('student_dashboard.html', events=events, registered_event_ids=registered_event_ids)

@app.route('/register_event/<int:event_id>')
def register_event(event_id):
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))

    user_id = session['user_id']
    already_registered = Registration.query.filter_by(user_id=user_id, event_id=event_id).first()

    if not already_registered:
        registration = Registration(user_id=user_id, event_id=event_id)
        db.session.add(registration)
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        venue = request.form['venue']

        new_event = Event(name=name, date=date, venue=venue)
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    events = Event.query.all()
    return render_template('admin_dashboard.html', events=events)

@app.route('/admin_event/<int:event_id>')
@app.route('/admin/event/<int:event_id>')
def admin_event(event_id):
    event = Event.query.get_or_404(event_id)
    registrations = Registration.query.filter_by(event_id=event_id).all()
    return render_template('admin_event.html', event=event, registrations=registrations)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------- Main -----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(role='admin').first():
            admin_user = User(
                name='Admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin account created!")
    app.run(host='0.0.0.0', port=5000, debug=True)
