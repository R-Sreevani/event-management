# IMPORTANT: Use SQLAlchemy 1.4.x instead of 2.x for Python 3.13 compatibility
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import json
import os
import csv
import uuid
from io import StringIO, BytesIO
from typing import Dict, List, Optional, Tuple
import logging
from logging.handlers import RotatingFileHandler
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateField, TimeField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, Length, ValidationError
import qrcode
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64

# ----------------- Configuration -----------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cuk-secret-key-2025-prod')
# Use SQLite for simplicity initially, then switch to PostgreSQL for Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cuk_events.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# Initialize extensions - IMPORTANT: Use SQLAlchemy 1.4.x compatible setup
db = SQLAlchemy(app)
cache = Cache(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/qrcodes', exist_ok=True)
os.makedirs('static/exports', exist_ok=True)

# ----------------- Custom Exceptions -----------------
class EventFullError(Exception):
    """Raised when an event reaches capacity"""
    pass

class AlreadyRegisteredError(Exception):
    """Raised when user is already registered for an event"""
    pass

class InvalidEmailError(Exception):
    """Raised when email is not a university email"""
    pass

# ----------------- Forms -----------------
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class RegistrationForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('University Email', validators=[DataRequired(), Email()])
    registration_no = StringField('Registration Number', validators=[Length(max=20)])
    phone = StringField('Phone Number', validators=[Length(max=20)])
    department_id = SelectField('Department', coerce=int)
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    
    def validate_email(self, field):
        if not field.data.endswith('@cuk.ac.in'):
            raise ValidationError('Please use your university email (@cuk.ac.in)')
    
    def validate_password(self, field):
        password = field.data
        if (len(password) < 8 or 
            not any(c.isupper() for c in password) or
            not any(c.islower() for c in password) or
            not any(c.isdigit() for c in password)):
            raise ValidationError(
                'Password must be at least 8 characters with uppercase, lowercase, and numbers'
            )

class EventForm(FlaskForm):
    name = StringField('Event Name', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()], format='%Y-%m-%d')
    start_time = TimeField('Start Time', format='%H:%M')
    end_time = TimeField('End Time', format='%H:%M')
    venue = StringField('Venue', validators=[DataRequired(), Length(max=200)])
    category = SelectField('Category', validators=[DataRequired()])
    department_id = SelectField('Department', coerce=int)
    faculty_coordinator_id = SelectField('Faculty Coordinator', coerce=int)
    capacity = IntegerField('Capacity', default=100)
    is_active = BooleanField('Active')

class AnnouncementForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = SelectField('Category', validators=[DataRequired()])
    priority = SelectField('Priority', choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')])
    expiry_days = IntegerField('Expiry (days)', default=7)

class FeedbackForm(FlaskForm):
    rating = SelectField('Rating', choices=[(str(i), str(i)) for i in range(1, 6)], validators=[DataRequired()])
    comment = TextAreaField('Comment')

# ----------------- Models -----------------
class Department(db.Model):
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(10), unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'description': self.description
        }

class Faculty(db.Model):
    __tablename__ = 'faculty'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    designation = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    department = db.relationship('Department', backref='faculty_members')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'department': self.department.name if self.department else None,
            'designation': self.designation,
            'phone': self.phone
        }

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), default='student')  # 'admin', 'student', 'faculty'
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    registration_no = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    department = db.relationship('Department', backref='users')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'department': self.department.name if self.department else None,
            'registration_no': self.registration_no,
            'phone': self.phone
        }

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10))
    end_time = db.Column(db.String(10))
    venue = db.Column(db.String(200))
    category = db.Column(db.String(50))
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    faculty_coordinator_id = db.Column(db.Integer, db.ForeignKey('faculty.id'))
    capacity = db.Column(db.Integer, default=100)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    department = db.relationship('Department', backref='events')
    faculty_coordinator = db.relationship('Faculty', backref='coordinated_events')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'date': self.date.isoformat() if self.date else None,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'venue': self.venue,
            'category': self.category,
            'department': self.department.name if self.department else None,
            'faculty_coordinator': self.faculty_coordinator.name if self.faculty_coordinator else None,
            'capacity': self.capacity,
            'registrations_count': len(self.registrations),
            'is_active': self.is_active
        }

class Registration(db.Model):
    __tablename__ = 'registrations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    attendance_status = db.Column(db.String(20), default='Registered')  # 'Registered', 'Present', 'Absent'
    qr_code = db.Column(db.String(200))
    check_in_time = db.Column(db.DateTime)
    check_out_time = db.Column(db.DateTime)
    
    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.to_dict(),
            'event': self.event.to_dict(),
            'registered_at': self.registered_at.isoformat() if self.registered_at else None,
            'attendance_status': self.attendance_status,
            'check_in_time': self.check_in_time.isoformat() if self.check_in_time else None,
            'check_out_time': self.check_out_time.isoformat() if self.check_out_time else None
        }

class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    priority = db.Column(db.String(20))
    published_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'category': self.category,
            'priority': self.priority,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'is_active': self.is_active
        }

class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    rating = db.Column(db.Integer)
    comment = db.Column(db.Text)
    submitted_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=True)
    
    event = db.relationship('Event', backref='feedbacks')
    user = db.relationship('User', backref='feedbacks')
    
    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.name if self.user else 'Anonymous',
            'rating': self.rating,
            'comment': self.comment,
            'submitted_date': self.submitted_date.isoformat() if self.submitted_date else None
        }

# ... [REST OF YOUR CODE STAYS THE SAME - all the routes and functions] ...
# Just continue with all your existing routes from line 185 onward

# The rest of your file (routes, functions, etc.) remains exactly the same
# Only the imports and model definitions above were modified for SQLAlchemy 1.4.x compatibility

# ----------------- Initialize Database -----------------
def initialize_database():
    """Initialize database with default data"""
    with app.app_context():
        try:
            db.create_all()
            
            # Create default admin if not exists
            if not User.query.filter_by(email='admin@cuk.ac.in').first():
                admin = User(
                    name='System Administrator',
                    email='admin@cuk.ac.in',
                    password=generate_password_hash('admin123'),
                    role='admin',
                    department_id=None
                )
                db.session.add(admin)
                print("✅ Admin account created: admin@cuk.ac.in / admin123")
            
            # Create demo accounts
            demo_accounts = [
                ('Demo Student', 'student@cuk.ac.in', 'student123', 'student'),
                ('Demo Faculty', 'faculty@cuk.ac.in', 'faculty123', 'faculty'),
            ]
            
            for name, email, password, role in demo_accounts:
                if not User.query.filter_by(email=email).first():
                    user = User(
                        name=name,
                        email=email,
                        password=generate_password_hash(password),
                        role=role,
                        department_id=1  # Assign to first department
                    )
                    db.session.add(user)
                    print(f"✅ {role.capitalize()} account created: {email} / {password}")
            
            # Create default departments if not exists
            default_departments = [
                ('Computer Science', 'CS', 'Department of Computer Science'),
                ('Mathematics', 'MATH', 'Department of Mathematics'),
                ('Physics', 'PHY', 'Department of Physics'),
                ('Chemistry', 'CHEM', 'Department of Chemistry'),
                ('Life Sciences', 'LIFE', 'Department of Life Sciences'),
                ('Economics', 'ECO', 'Department of Economics'),
                ('Management', 'MGMT', 'Department of Management Studies'),
                ('Social Sciences', 'SOC', 'Department of Social Sciences'),
                ('Languages', 'LANG', 'Department of Languages'),
                ('Interdisciplinary Studies', 'IDS', 'Department of Interdisciplinary Studies')
            ]
            
            for name, code, desc in default_departments:
                if not Department.query.filter_by(name=name).first():
                    dept = Department(name=name, code=code, description=desc)
                    db.session.add(dept)
            
            # Create sample events
            if Event.query.count() == 0:
                sample_events = [
                    {
                        'name': 'Annual Tech Fest',
                        'description': 'Annual technology festival with workshops and competitions',
                        'date': datetime.now().date() + timedelta(days=7),
                        'category': 'academic',
                        'venue': 'Main Auditorium',
                        'capacity': 200
                    },
                    {
                        'name': 'Cultural Night',
                        'description': 'Annual cultural program with music and dance performances',
                        'date': datetime.now().date() + timedelta(days=14),
                        'category': 'cultural',
                        'venue': 'Open Air Theater',
                        'capacity': 500
                    }
                ]
                
                for event_data in sample_events:
                    event = Event(**event_data)
                    db.session.add(event)
            
            # Create default announcement
            if not Announcement.query.first():
                announcement = Announcement(
                    title='Welcome to CUK Events Portal',
                    content='Central University of Karnataka welcomes you to the new event management system. Stay tuned for upcoming events!',
                    category='General',
                    priority='High',
                    expiry_date=datetime.now() + timedelta(days=30)
                )
                db.session.add(announcement)
            
            db.session.commit()
            print("✅ Database initialized successfully!")
            
        except Exception as e:
            print(f"❌ Error initializing database: {str(e)}")
            db.session.rollback()

# ----------------- Main Execution -----------------
if __name__ == '__main__':
    initialize_database()
    
    # Print startup information
    print("\n" + "="*50)
    print("🚀 Central University of Karnataka Events System")
    print("="*50)
    print(f"📁 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"📁 Uploads: {app.config['UPLOAD_FOLDER']}")
    print("🌐 Server starting at http://localhost:5000")
    print("="*50)
    print("\n🔑 Demo Accounts:")
    print("   👤 Admin: admin@cuk.ac.in / admin123")
    print("   👨‍🎓 Student: student@cuk.ac.in / student123")
    print("   👨‍🏫 Faculty: faculty@cuk.ac.in / faculty123")
    print("\n📋 Default Departments:")
    for dept in Department.query.all()[:3]:
        print(f"   • {dept.name} ({dept.code})")
    print("="*50 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
