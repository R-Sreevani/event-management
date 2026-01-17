from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
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
    description = db.Column(db.Text, nullable=True)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')

# ----------------- Simple Chatbot Function -----------------
def get_chatbot_response(message):
    message = message.lower()
    
    # Simple keyword matching
    if any(word in message for word in ['hello', 'hi', 'hey']):
        return "Hello! 👋 How can I help you?"
    
    elif any(word in message for word in ['event', 'events', 'upcoming']):
        events = Event.query.all()
        if not events:
            return "There are no upcoming events at the moment."
        response = "📅 **Upcoming Events:**\n"
        for event in events[:3]:
            response += f"• {event.name} on {event.date}\n"
        return response
    
    elif any(word in message for word in ['forgot', 'password', 'reset']):
        return "🔐 **Password Help:**\n\nFor password reset, please contact:\n📧 Email: admin@example.com\n\n🔑 **Demo Accounts:**\n• Admin: admin@example.com / admin123\n• Student: student@example.com / student123"
    
    elif any(word in message for word in ['register', 'sign up']):
        return "📝 **Registration:**\n\n1. Go to Register page\n2. Fill your details\n3. Choose Student role\n4. Click Create Account"
    
    elif any(word in message for word in ['login', 'sign in']):
        return "🔐 **Login Help:**\n\n1. Go to Login page\n2. Enter email & password\n3. Click Login\n\nDemo accounts available!"
    
    elif any(word in message for word in ['admin', 'contact']):
        return "👨‍💼 **Admin Contact:**\n📧 Email: admin@example.com\n\nFor urgent issues, please email directly."
    
    elif any(word in message for word in ['time', 'clock']):
        return f"🕒 Current time: {datetime.now().strftime('%I:%M %p')}"
    
    elif any(word in message for word in ['date', 'today']):
        return f"📅 Today's date: {datetime.now().strftime('%B %d, %Y')}"
    
    else:
        return "I can help with:\n• Event information\n• Registration process\n• Login issues\n• Password reset\n\nTry asking: 'events', 'password help', or 'login'"

# ----------------- Routes -----------------
@app.route('/')
def index():
    events = Event.query.all()
    return render_template('index.html', events=events)

# REMOVE chatbot route from login/register pages
@app.route('/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        # Only allow chatbot for logged-in users or on homepage
        if 'user_id' not in session and request.referrer and ('/login' in request.referrer or '/register' in request.referrer):
            return jsonify({'response': "Please complete registration/login first. For password help: admin@example.com"})
        
        response = get_chatbot_response(user_message)
        return jsonify({'response': response})
        
    except Exception as e:
        return jsonify({'response': f"Error: {str(e)}. Please try again."})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        if role == 'admin' and User.query.filter_by(role='admin').first():
            flash("⚠️ Admin already exists. You can only register as a student.")
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash("⚠️ User already exists with this email.")
            return render_template('register.html')

        user = User(name=name, email=email, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        
        flash("✅ Registration successful! Please login.")
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
            session['user_name'] = user.name
            flash(f"✅ Welcome back, {user.name}!")
            return redirect(url_for('dashboard'))

        flash("❌ Invalid email or password")
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login to access dashboard")
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
        flash("Please login as student to register for events")
        return redirect(url_for('login'))

    user_id = session['user_id']
    already_registered = Registration.query.filter_by(user_id=user_id, event_id=event_id).first()

    if not already_registered:
        registration = Registration(user_id=user_id, event_id=event_id)
        db.session.add(registration)
        db.session.commit()
        flash("✅ Successfully registered for the event!")

    return redirect(url_for('dashboard'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Admin access required")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        venue = request.form['venue']
        description = request.form.get('description', '')

        new_event = Event(name=name, date=date, venue=venue, description=description)
        db.session.add(new_event)
        db.session.commit()
        flash("✅ Event created successfully!")
        return redirect(url_for('admin_dashboard'))

    events = Event.query.all()
    return render_template('admin_dashboard.html', events=events)

@app.route('/admin_event/<int:event_id>')
@app.route('/admin/event/<int:event_id>')
def admin_event(event_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Admin access required")
        return redirect(url_for('login'))
        
    event = Event.query.get_or_404(event_id)
    registrations = Registration.query.filter_by(event_id=event_id).all()
    return render_template('admin_event.html', event=event, registrations=registrations)

@app.route('/logout')
def logout():
    session.clear()
    flash("✅ Successfully logged out!")
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
            print("✅ Admin account created: admin@example.com / admin123")
        # Create a demo student account if not exists
        if not User.query.filter_by(email='student@example.com').first():
            student_user = User(
                name='Demo Student',
                email='student@example.com',
                password=generate_password_hash('student123'),
                role='student'
            )
            db.session.add(student_user)
            db.session.commit()
            print("✅ Demo student account created: student@example.com / student123")
    app.run(host='0.0.0.0', port=5000, debug=True)
