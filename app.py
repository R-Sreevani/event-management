from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import random
import smtplib
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

# ✅ Inject current datetime object into all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ----------------- OTP Configuration -----------------
# Email configuration (update with your SMTP details)
SMTP_SERVER = "smtp.gmail.com"  # Change as needed
SMTP_PORT = 587
SMTP_USERNAME = "your-email@gmail.com"  # Change this
SMTP_PASSWORD = "your-app-password"  # Change this

# OTP storage dictionary (in production, use database)
# Format: {email: {'otp': '123456', 'expiry': datetime, 'verified': False}}
otp_storage = {}

# Password reset token expiry (in minutes)
OTP_EXPIRY_MINUTES = 5

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
    
    def to_dict(self):
        """Convert Event object to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'date': self.date,
            'venue': self.venue,
            'description': self.description
        }

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)

    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')

# ----------------- Helper Functions for OTP -----------------
def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    """Send OTP to user's email (dummy function - update with real SMTP)"""
    try:
        # For now, just print to console
        print(f"📧 OTP for {email}: {otp}")
        print("In production, configure SMTP settings above to send real emails")
        
        # Uncomment and configure this for real email sending:
        """
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Password Reset OTP - Event Management System"
        
        body = f"""
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>You have requested to reset your password for Event Management System.</p>
            <p>Your OTP is: <strong>{otp}</strong></p>
            <p>This OTP will expire in {OTP_EXPIRY_MINUTES} minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        """
        
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

def store_otp(email, otp):
    """Store OTP with expiry time"""
    expiry_time = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    otp_storage[email] = {
        'otp': otp,
        'expiry': expiry_time,
        'verified': False
    }
    return True

def verify_otp(email, otp):
    """Verify if OTP is valid"""
    if email not in otp_storage:
        return False, "No OTP request found for this email"
    
    otp_data = otp_storage[email]
    
    # Check if OTP has expired
    if datetime.now() > otp_data['expiry']:
        del otp_storage[email]
        return False, "OTP has expired. Please request a new one."
    
    # Check if OTP matches
    if otp_data['otp'] != otp:
        return False, "Invalid OTP"
    
    # Mark OTP as verified
    otp_data['verified'] = True
    return True, "OTP verified successfully"

def clear_otp(email):
    """Clear OTP data after use"""
    if email in otp_storage:
        del otp_storage[email]

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
            'password': ['forgot password', 'reset password', 'password reset', 'lost password', 'change password']
        }
    
    def get_response(self, user_input, user_role=None, user_id=None):
        user_input = user_input.lower().strip()
        
        # Check for greeting
        if any(word in user_input for word in self.responses['greeting']):
            return "Hello! 👋 I'm your event assistant. How can I help you today?"
        
        # Check for password reset
        elif any(word in user_input for word in self.responses['password']):
            return "To reset your password:\n1. Click the 'Forgot Password' button in the chatbot\n2. Enter your email to receive OTP\n3. Enter the OTP sent to your email\n4. Create a new password"
        
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
            return "I'm not sure I understand. Try asking about:\n• Upcoming events\n• How to register\n• Event details\n• Forgot password\n• Contacting admin"

# ----------------- Routes -----------------
@app.route('/')
def index():
    events = Event.query.all()
    # Convert events to dictionaries for safe JSON serialization
    events_data = [event.to_dict() for event in events]
    return render_template('index.html', events=events_data)

@app.route('/chatbot', methods=['POST'])
def chatbot():
    if 'user_id' not in session:
        return jsonify({'response': 'Please login to use the chatbot.'})
    
    data = request.get_json()
    user_message = data.get('message', '')
    
    chatbot = EventChatbot(db)
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    response = chatbot.get_response(user_message, user_role, user_id)
    
    return jsonify({'response': response})

# ----------------- Password Reset Routes -----------------
@app.route('/send-otp', methods=['POST'])
def send_otp():
    """Send OTP to user's email for password reset"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
    
    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal that user doesn't exist (security)
        return jsonify({'success': True, 'message': 'If an account exists with this email, OTP will be sent.'})
    
    # Generate and store OTP
    otp = generate_otp()
    store_otp(email, otp)
    
    # Send OTP via email
    if send_otp_email(email, otp):
        return jsonify({
            'success': True, 
            'message': 'OTP sent to your email address.',
            'email': email
        })
    else:
        return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    """Verify OTP entered by user"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '')
    
    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email and OTP are required'})
    
    # Verify OTP
    is_valid, message = verify_otp(email, otp)
    
    if is_valid:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'message': message})

@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset user's password after OTP verification"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not email or not new_password or not confirm_password:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'})
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
    
    # Check if OTP was verified
    if email not in otp_storage or not otp_storage[email].get('verified'):
        return jsonify({'success': False, 'message': 'OTP not verified. Please complete OTP verification first.'})
    
    # Find user and update password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    try:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        
        # Clear OTP after successful password reset
        clear_otp(email)
        
        return jsonify({'success': True, 'message': 'Password updated successfully! You can now login with your new password.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating password: {str(e)}'})

# ----------------- Existing Routes (Unchanged) -----------------
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
        description = request.form.get('description', '')

        new_event = Event(name=name, date=date, venue=venue, description=description)
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
