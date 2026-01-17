from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import uuid

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
    description = db.Column(db.Text, nullable=True)  # Added for chatbot

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')

# ----------------- Chatbot Logic -----------------
class EventChatbot:
    def __init__(self, db_session):
        self.db = db_session
        self.responses = {
            'greeting': ['hello', 'hi', 'hey', 'greetings'],
            'events': ['events', 'upcoming events', 'what events', 'show events'],
            'registration': ['register', 'how to register', 'sign up', 'join event'],
            'admin': ['admin', 'contact admin', 'help', 'support'],
            'time': ['time', 'current time', 'what time', 'clock'],
            'date': ['date', 'today', 'what day', 'calendar'],
            'logout': ['logout', 'sign out', 'exit', 'quit'],
            'login': ['login', 'sign in', 'log in'],
            'forgot_password': ['forgot password', 'reset password', 'password reset', 'lost password']
        }
    
    def get_response(self, user_input, user_role=None, user_id=None):
        user_input = user_input.lower().strip()
        
        # Check for greeting
        if any(word in user_input for word in self.responses['greeting']):
            if user_role:
                return f"Hello {user_role.capitalize()}! 👋 How can I help you today?"
            else:
                return "Hello! 👋 I'm your event assistant. How can I help you today?"
        
        # Check for events query
        elif any(word in user_input for word in self.responses['events']):
            events = Event.query.all()
            if not events:
                return "There are no upcoming events at the moment."
            
            response = "📅 **Upcoming Events:**\n"
            for event in events[:5]:  # Show first 5 events
                response += f"• {event.name} on {event.date} at {event.venue or 'TBD'}\n"
            if len(events) > 5:
                response += f"... and {len(events)-5} more events."
            return response
        
        # Check for forgot password
        elif any(word in user_input for word in self.responses['forgot_password']):
            return "For password reset:\n📧 Email: admin@example.com\n🔧 Contact the admin with your registered email address for password assistance."
        
        # Check for login help
        elif any(word in user_input for word in self.responses['login']):
            return "To login:\n1. Go to the login page\n2. Enter your email and password\n3. Click Login\n\nDemo accounts:\n• Admin: admin@example.com / admin123\n• Student: student@example.com / student123"
        
        # Check for registration info
        elif any(word in user_input for word in self.responses['registration']):
            return "To register for an event:\n1. Go to your dashboard\n2. Click 'Register' on any event\n3. You'll see your registered events in your dashboard!"
        
        # Check for admin/support
        elif any(word in user_input for word in self.responses['admin']):
            return "For admin support:\n📧 Email: admin@example.com\n🔧 You can also create events in the admin dashboard if you're an admin!"
        
        # Check for time
        elif any(word in user_input for word in self.responses['time']):
            return f"The current time is: {datetime.now().strftime('%I:%M %p')}"
        
        # Check for date
        elif any(word in user_input for word in self.responses['date']):
            return f"Today's date is: {datetime.now().strftime('%B %d, %Y')}"
        
        # Check for logout
        elif any(word in user_input for word in self.responses['logout']):
            return "You can logout by clicking the 'Logout' button in the top right corner of the page."
        
        # Personal event queries (if user is logged in)
        elif user_id and ('my events' in user_input or 'registered' in user_input):
            registrations = Registration.query.filter_by(user_id=user_id).all()
            if not registrations:
                return "You haven't registered for any events yet!"
            
            response = "🎟️ **Your Registered Events:**\n"
            for reg in registrations[:5]:
                event = reg.event
                response += f"• {event.name} on {event.date}\n"
            return response
        
        # Event specific queries
        elif 'event' in user_input:
            # Try to find event names mentioned
            events = Event.query.all()
            for event in events:
                if event.name.lower() in user_input:
                    return f"**{event.name}**\n📅 Date: {event.date}\n📍 Venue: {event.venue or 'To be announced'}\n📝 {event.description or 'No description available.'}"
            
            return "I couldn't find specific event details. Try asking 'What events are coming up?'"
        
        # Default response
        else:
            return "I'm not sure I understand. Try asking about:\n• Upcoming events\n• How to register\n• Event details\n• Contacting admin"

# ----------------- Routes -----------------
@app.route('/')
def index():
    try:
        events = Event.query.all()
        return render_template('index.html', events=events)
    except Exception as e:
        # Log error and return empty events list
        print(f"Error loading events: {str(e)}")
        return render_template('index.html', events=[])

@app.route('/chatbot', methods=['POST'])
def chatbot():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        
        chatbot = EventChatbot(db)
        
        # Get user info if logged in
        user_role = session.get('role') if 'user_id' in session else None
        user_id = session.get('user_id') if 'user_id' in session else None
        
        # Handle unauthenticated users
        if 'user_id' not in session:
            # Allow basic event queries
            if any(word in user_message.lower() for word in ['event', 'events', 'upcoming', 'schedule', 'what events']):
                events = Event.query.all()
                if not events:
                    response = "There are no upcoming events at the moment."
                else:
                    response = "📅 **Upcoming Events:**\n"
                    for event in events[:5]:
                        response += f"• {event.name} on {event.date} at {event.venue or 'TBD'}\n"
                    if len(events) > 5:
                        response += f"... and {len(events)-5} more events."
                    response += "\n\nPlease login or register to participate!"
                return jsonify({'response': response})
            elif any(word in user_message.lower() for word in ['forgot password', 'reset password', 'password reset']):
                return jsonify({'response': "For password reset:\n📧 Email: admin@example.com\n🔧 Contact the admin with your registered email address."})
            else:
                return jsonify({'response': "Please login or register to access full chatbot features. I can tell you about upcoming events if you ask!"})
        
        response = chatbot.get_response(user_message, user_role, user_id)
        return jsonify({'response': response})
        
    except Exception as e:
        print(f"Chatbot error: {str(e)}")
        return jsonify({'response': 'Sorry, I encountered an error. Please try again.'})

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

    try:
        user_id = session['user_id']
        events = Event.query.all()
        registered_event_ids = [reg.event_id for reg in Registration.query.filter_by(user_id=user_id).all()]
        return render_template('student_dashboard.html', events=events, registered_event_ids=registered_event_ids)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}")
        return redirect(url_for('index'))

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

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

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
            print("✅ Demo student account created!")
    app.run(host='0.0.0.0', port=5000, debug=True)
