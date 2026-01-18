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

# FIXED: Flask-Limiter 3.5.0 initialization (key_func is first argument)
limiter = Limiter(
    get_remote_address,  # FIRST argument, not keyword argument
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
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

class EventGallery(db.Model):
    __tablename__ = 'event_gallery'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))
    image_url = db.Column(db.String(500))
    caption = db.Column(db.String(200))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    
    event = db.relationship('Event', backref='gallery_images')
    uploader = db.relationship('User', backref='uploaded_images')

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    type = db.Column(db.String(50))  # 'info', 'success', 'warning', 'error'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='notifications')

# ----------------- Utility Functions -----------------
def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code(data: str, filename: str) -> str:
    """Generate QR code for registration"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    path = f'static/qrcodes/{filename}.png'
    img.save(path)
    return path

def get_event_categories() -> List[Dict]:
    """Get list of event categories"""
    return [
        {'id': 'academic', 'name': '🎓 Academic', 'icon': 'graduation-cap', 'color': '#0077cc'},
        {'id': 'cultural', 'name': '🎭 Cultural', 'icon': 'mask', 'color': '#e83e8c'},
        {'id': 'sports', 'name': '⚽ Sports', 'icon': 'futbol', 'color': '#28a745'},
        {'id': 'workshop', 'name': '🔧 Workshop', 'icon': 'tools', 'color': '#ffc107'},
        {'id': 'seminar', 'name': '🎤 Seminar', 'icon': 'chalkboard-teacher', 'color': '#17a2b8'},
        {'id': 'conference', 'name': '🏛️ Conference', 'icon': 'users', 'color': '#6f42c1'},
        {'id': 'competition', 'name': '🏆 Competition', 'icon': 'trophy', 'color': '#fd7e14'},
        {'id': 'others', 'name': '📌 Others', 'icon': 'star', 'color': '#6c757d'}
    ]

def get_dashboard_stats() -> Dict:
    """Get comprehensive dashboard statistics"""
    stats = {
        'total_events': Event.query.filter_by(is_active=True).count(),
        'upcoming_events': Event.query.filter(
            Event.date >= datetime.now().date(),
            Event.is_active == True
        ).count(),
        'ongoing_events': Event.query.filter(
            Event.date == datetime.now().date(),
            Event.is_active == True
        ).count(),
        'total_registrations': Registration.query.count(),
        'total_users': User.query.filter_by(is_active=True).count(),
        'total_departments': Department.query.count(),
        'total_faculty': Faculty.query.filter_by(is_active=True).count(),
        'active_announcements': Announcement.query.filter(
            Announcement.is_active == True,
            Announcement.expiry_date >= datetime.now()
        ).count()
    }
    
    # Department-wise event count
    dept_stats = db.session.query(
        Department.name,
        db.func.count(Event.id)
    ).join(Event, isouter=True).group_by(Department.name).all()
    
    stats['department_stats'] = dept_stats
    
    # Attendance statistics
    stats['attendance_present'] = Registration.query.filter_by(attendance_status='Present').count()
    stats['attendance_absent'] = Registration.query.filter_by(attendance_status='Absent').count()
    stats['attendance_pending'] = Registration.query.filter_by(attendance_status='Registered').count()
    
    return stats

def create_notification(user_id: int, title: str, message: str, type: str = 'info'):
    """Create a notification for user"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=type
    )
    db.session.add(notification)
    db.session.commit()

# ----------------- Decorators -----------------
def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def faculty_required(f):
    """Decorator to require faculty role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['admin', 'faculty']:
            flash('Faculty access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or session.get('role') not in roles:
                flash(f'Access denied. Required roles: {", ".join(roles)}', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ----------------- Context Processors -----------------
@app.context_processor
def inject_now():
    """Inject current datetime into all templates"""
    return {'now': datetime.now()}

@app.context_processor
def inject_user_info():
    """Inject user info into templates"""
    user_info = {
        'is_authenticated': 'user_id' in session,
        'user_id': session.get('user_id'),
        'user_name': session.get('user_name'),
        'role': session.get('role'),
        'department_id': session.get('department_id')
    }
    
    if user_info['is_authenticated']:
        user_info['unread_notifications'] = Notification.query.filter_by(
            user_id=session['user_id'],
            is_read=False
        ).count()
    
    return user_info

@app.context_processor
def inject_categories():
    """Inject event categories into templates"""
    return {'event_categories': get_event_categories()}

# ----------------- Error Handlers -----------------
@app.errorhandler(404)
def page_not_found(e):
    """404 error handler"""
    logger.warning(f'404 error: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 error handler"""
    logger.error(f'500 error: {str(e)}')
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    """403 error handler"""
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def ratelimit_handler(e):
    """Rate limit error handler"""
    flash('Too many requests. Please try again later.', 'warning')
    return redirect(request.referrer or url_for('index'))

# ----------------- API Routes -----------------
@app.route('/api/events', methods=['GET'])
def api_events():
    """Get events API endpoint"""
    category = request.args.get('category', 'all')
    department = request.args.get('department', 'all')
    search = request.args.get('search', '')
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    query = Event.query.filter_by(is_active=True)
    
    if category != 'all':
        query = query.filter_by(category=category)
    
    if department != 'all':
        query = query.filter_by(department_id=department)
    
    if search:
        query = query.filter(Event.name.ilike(f'%{search}%'))
    
    total = query.count()
    events = query.order_by(Event.date).offset(offset).limit(limit).all()
    
    return jsonify({
        'success': True,
        'total': total,
        'events': [event.to_dict() for event in events],
        'offset': offset,
        'limit': limit
    })

@app.route('/api/events/<int:event_id>', methods=['GET'])
def api_event_detail(event_id):
    """Get event detail API endpoint"""
    event = Event.query.get_or_404(event_id)
    return jsonify({
        'success': True,
        'event': event.to_dict(),
        'feedbacks': [fb.to_dict() for fb in event.feedbacks]
    })

@app.route('/api/attendance/<int:registration_id>', methods=['PUT'])
@admin_required
def api_update_attendance(registration_id):
    """Update attendance API endpoint"""
    try:
        data = request.get_json()
        registration = Registration.query.get_or_404(registration_id)
        
        old_status = registration.attendance_status
        new_status = data.get('status')
        
        if new_status not in ['Present', 'Absent', 'Registered']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400
        
        registration.attendance_status = new_status
        
        if new_status == 'Present' and not registration.check_in_time:
            registration.check_in_time = datetime.now()
        elif new_status != 'Present' and registration.check_in_time:
            registration.check_in_time = None
        
        db.session.commit()
        
        # Log the change
        logger.info(f'Attendance updated: {old_status} -> {new_status} for registration {registration_id}')
        
        return jsonify({
            'success': True,
            'message': 'Attendance updated successfully'
        })
    except Exception as e:
        logger.error(f'Error updating attendance: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/registrations/<int:registration_id>', methods=['DELETE'])
@login_required
def api_delete_registration(registration_id):
    """Delete registration API endpoint"""
    try:
        registration = Registration.query.get_or_404(registration_id)
        
        # Check if user owns the registration or is admin
        if registration.user_id != session['user_id'] and session.get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        
        db.session.delete(registration)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Registration deleted successfully'
        })
    except Exception as e:
        logger.error(f'Error deleting registration: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/analytics/event/<int:event_id>')
@admin_required
def api_event_analytics(event_id):
    """Get event analytics API endpoint"""
    event = Event.query.get_or_404(event_id)
    
    # Attendance data
    attendance_data = {
        'Present': Registration.query.filter_by(event_id=event_id, attendance_status='Present').count(),
        'Absent': Registration.query.filter_by(event_id=event_id, attendance_status='Absent').count(),
        'Registered': Registration.query.filter_by(event_id=event_id, attendance_status='Registered').count()
    }
    
    # Department distribution
    dept_distribution = db.session.query(
        Department.name,
        db.func.count(Registration.id)
    ).join(User, User.id == Registration.user_id)\
     .join(Department, Department.id == User.department_id)\
     .filter(Registration.event_id == event_id)\
     .group_by(Department.name).all()
    
    return jsonify({
        'success': True,
        'attendance': attendance_data,
        'department_distribution': dict(dept_distribution)
    })

# ----------------- Main Routes -----------------
@app.route('/')
@cache.cached(timeout=300)
def index():
    """Home page"""
    try:
        announcements = Announcement.query.filter(
            Announcement.is_active == True,
            Announcement.expiry_date >= datetime.now()
        ).order_by(Announcement.priority.desc(), Announcement.published_date.desc()).limit(5).all()
        
        upcoming_events = Event.query.filter(
            Event.date >= datetime.now().date(),
            Event.is_active == True
        ).order_by(Event.date).limit(6).all()
        
        departments = Department.query.all()
        categories = get_event_categories()
        
        return render_template('index.html',
                             announcements=announcements,
                             events=upcoming_events,
                             departments=departments,
                             categories=categories)
    except Exception as e:
        logger.error(f'Error loading index: {str(e)}')
        return render_template('errors/500.html'), 500

@app.route('/events')
def events():
    """Events listing page"""
    category = request.args.get('category', 'all')
    department = request.args.get('department', 'all')
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'date')
    
    query = Event.query.filter_by(is_active=True)
    
    if category != 'all':
        query = query.filter_by(category=category)
    
    if department != 'all':
        query = query.filter_by(department_id=department)
    
    if search:
        query = query.filter(Event.name.ilike(f'%{search}%'))
    
    # Sorting
    if sort == 'date':
        query = query.order_by(Event.date)
    elif sort == 'name':
        query = query.order_by(Event.name)
    elif sort == 'popular':
        # Sort by number of registrations
        query = query.outerjoin(Registration).group_by(Event.id).order_by(db.func.count(Registration.id).desc())
    
    events = query.all()
    departments = Department.query.all()
    categories = get_event_categories()
    
    return render_template('events.html',
                         events=events,
                         departments=departments,
                         categories=categories,
                         selected_category=category,
                         selected_department=department,
                         sort=sort)

@app.route('/calendar')
def calendar():
    """Event calendar page"""
    events = Event.query.filter_by(is_active=True).all()
    calendar_events = []
    
    for event in events:
        color_map = {
            'academic': '#0077cc',
            'cultural': '#e83e8c',
            'sports': '#28a745',
            'workshop': '#ffc107',
            'seminar': '#17a2b8',
            'conference': '#6f42c1',
            'competition': '#fd7e14',
            'others': '#6c757d'
        }
        
        calendar_events.append({
            'title': event.name,
            'start': event.date.isoformat(),
            'end': (event.date + timedelta(days=1)).isoformat() if event.date else event.date.isoformat(),
            'color': color_map.get(event.category, '#0077cc'),
            'url': url_for('event_detail', event_id=event.id),
            'extendedProps': {
                'venue': event.venue,
                'category': event.category,
                'capacity': event.capacity
            }
        })
    
    return render_template('calendar.html', events=calendar_events)

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    """Event detail page"""
    event = Event.query.get_or_404(event_id)
    
    if not event.is_active:
        flash('This event is no longer active', 'warning')
        return redirect(url_for('events'))
    
    is_registered = False
    registration = None
    user_feedback = None
    
    if 'user_id' in session:
        registration = Registration.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first()
        is_registered = registration is not None
        
        user_feedback = Feedback.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first()
    
    # Calculate average rating
    avg_rating_result = db.session.query(db.func.avg(Feedback.rating)).filter_by(
        event_id=event_id,
        is_approved=True
    ).scalar()
    avg_rating = round(avg_rating_result, 1) if avg_rating_result else 0
    
    # Get feedbacks
    feedbacks = Feedback.query.filter_by(
        event_id=event_id,
        is_approved=True
    ).order_by(Feedback.submitted_date.desc()).limit(10).all()
    
    # Get gallery images
    gallery = EventGallery.query.filter_by(
        event_id=event_id,
        is_approved=True
    ).all()
    
    # Get event statistics
    event_stats = {
        'total_registrations': len(event.registrations),
        'present_count': Registration.query.filter_by(
            event_id=event_id,
            attendance_status='Present'
        ).count(),
        'absent_count': Registration.query.filter_by(
            event_id=event_id,
            attendance_status='Absent'
        ).count(),
        'pending_count': Registration.query.filter_by(
            event_id=event_id,
            attendance_status='Registered'
        ).count()
    }
    
    return render_template('event_detail.html',
                         event=event,
                         is_registered=is_registered,
                         registration=registration,
                         user_feedback=user_feedback,
                         avg_rating=avg_rating,
                         feedbacks=feedbacks,
                         gallery=gallery,
                         event_stats=event_stats)

@app.route('/register_event/<int:event_id>', methods=['POST'])
@login_required
def register_event(event_id):
    """Register for an event"""
    try:
        event = Event.query.get_or_404(event_id)
        
        if not event.is_active:
            flash('This event is no longer accepting registrations', 'warning')
            return redirect(url_for('event_detail', event_id=event_id))
        
        # Check capacity
        registrations_count = Registration.query.filter_by(event_id=event_id).count()
        if registrations_count >= event.capacity:
            raise EventFullError('Event is full!')
        
        # Check if already registered
        existing = Registration.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first()
        
        if existing:
            raise AlreadyRegisteredError('Already registered for this event!')
        
        # Generate QR code data
        qr_data = json.dumps({
            'user_id': session['user_id'],
            'event_id': event_id,
            'timestamp': datetime.now().isoformat()
        })
        
        # Create registration with QR code
        registration = Registration(
            user_id=session['user_id'],
            event_id=event_id
        )
        
        db.session.add(registration)
        db.session.flush()  # Get the registration ID
        
        # Generate QR code
        qr_filename = f"registration_{registration.id}"
        qr_path = generate_qr_code(qr_data, qr_filename)
        registration.qr_code = qr_path
        
        db.session.commit()
        
        # Create notification
        create_notification(
            session['user_id'],
            'Event Registration Successful',
            f'You have successfully registered for "{event.name}"',
            'success'
        )
        
        flash('Successfully registered for the event!', 'success')
        logger.info(f'User {session["user_id"]} registered for event {event_id}')
        
    except EventFullError as e:
        flash(str(e), 'warning')
    except AlreadyRegisteredError as e:
        flash(str(e), 'info')
    except Exception as e:
        flash('An error occurred during registration', 'danger')
        logger.error(f'Registration error: {str(e)}')
    
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/unregister_event/<int:event_id>')
@login_required
def unregister_event(event_id):
    """Unregister from an event"""
    registration = Registration.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if registration:
        db.session.delete(registration)
        db.session.commit()
        
        flash('Successfully unregistered from the event', 'info')
        logger.info(f'User {session["user_id"]} unregistered from event {event_id}')
    
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/submit_feedback/<int:event_id>', methods=['POST'])
@login_required
def submit_feedback(event_id):
    """Submit feedback for an event"""
    rating = request.form.get('rating')
    comment = request.form.get('comment', '')
    
    if not rating:
        flash('Please provide a rating', 'warning')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Check if already submitted feedback
    existing = Feedback.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if existing:
        existing.rating = rating
        existing.comment = comment
        flash('Feedback updated successfully!', 'success')
    else:
        feedback = Feedback(
            user_id=session['user_id'],
            event_id=event_id,
            rating=rating,
            comment=comment
        )
        db.session.add(feedback)
        flash('Thank you for your feedback!', 'success')
    
    db.session.commit()
    return redirect(url_for('event_detail', event_id=event_id))

# ----------------- Authentication Routes -----------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for(session.get('role') + '_dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email, is_active=True).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['user_name'] = user.name
            session['department_id'] = user.department_id
            
            # Update last login
            user.last_login = datetime.now()
            db.session.commit()
            
            flash(f'Welcome back, {user.name}!', 'success')
            logger.info(f'User {user.id} logged in')
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'faculty':
                return redirect(url_for('faculty_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    """User registration page"""
    if 'user_id' in session:
        return redirect(url_for(session.get('role') + '_dashboard'))
    
    form = RegistrationForm()
    form.department_id.choices = [(0, 'Select Department')] + [
        (dept.id, f"{dept.name} ({dept.code})") 
        for dept in Department.query.order_by('name').all()
    ]
    
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = generate_password_hash(form.password.data)
        registration_no = form.registration_no.data
        phone = form.phone.data
        department_id = form.department_id.data if form.department_id.data != 0 else None
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return render_template('auth/register.html', form=form)
        
        user = User(
            name=name,
            email=email,
            password=password,
            role='student',
            registration_no=registration_no,
            phone=phone,
            department_id=department_id
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        logger.info(f'New user registered: {email}')
        
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', form=form)

@app.route('/logout')
def logout():
    """Logout user"""
    user_id = session.get('user_id')
    session.clear()
    flash('Successfully logged out!', 'info')
    
    if user_id:
        logger.info(f'User {user_id} logged out')
    
    return redirect(url_for('index'))

# ----------------- Student Routes -----------------
@app.route('/student/dashboard')
@login_required
@role_required('student', 'admin', 'faculty')
def student_dashboard():
    """Student dashboard"""
    user_id = session['user_id']
    
    # Get user's registered events
    registrations = Registration.query.filter_by(user_id=user_id).all()
    registered_events = [reg.event for reg in registrations if reg.event.is_active]
    
    # Get upcoming events from user's department
    department_events = []
    if session.get('department_id'):
        department_events = Event.query.filter(
            Event.department_id == session['department_id'],
            Event.date >= datetime.now().date(),
            Event.is_active == True
        ).order_by(Event.date).limit(5).all()
    
    # Get announcements
    announcements = Announcement.query.filter(
        Announcement.is_active == True,
        Announcement.expiry_date >= datetime.now()
    ).order_by(Announcement.published_date.desc()).limit(5).all()
    
    # Get notifications
    notifications = Notification.query.filter_by(
        user_id=user_id,
        is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Get statistics
    upcoming_count = sum(1 for event in registered_events if event.date >= datetime.now().date())
    completed_count = sum(1 for event in registered_events if event.date < datetime.now().date())
    
    # Get upcoming deadlines (events happening in next 3 days)
    upcoming_deadlines = [event for event in registered_events 
                         if event.date >= datetime.now().date() 
                         and (event.date - datetime.now().date()).days <= 3]
    
    return render_template('student/dashboard.html',
                         registered_events=registered_events,
                         department_events=department_events,
                         announcements=announcements,
                         notifications=notifications,
                         upcoming_count=upcoming_count,
                         completed_count=completed_count,
                         upcoming_deadlines=upcoming_deadlines)

@app.route('/student/registrations')
@login_required
@role_required('student')
def my_registrations():
    """My registrations page"""
    registrations = Registration.query.filter_by(
        user_id=session['user_id']
    ).order_by(Registration.registered_at.desc()).all()
    
    return render_template('student/registrations.html', registrations=registrations)

@app.route('/student/profile', methods=['GET', 'POST'])
@login_required
@role_required('student')
def student_profile():
    """Student profile page"""
    user = User.query.get_or_404(session['user_id'])
    
    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.phone = request.form.get('phone', user.phone)
        user.department_id = request.form.get('department_id', user.department_id)
        
        # Password change
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if current_password and new_password:
            if check_password_hash(user.password, current_password):
                user.password = generate_password_hash(new_password)
                flash('Password updated successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')
        
        db.session.commit()
        session['user_name'] = user.name
        flash('Profile updated successfully', 'success')
        return redirect(url_for('student_profile'))
    
    departments = Department.query.all()
    return render_template('student/profile.html', user=user, departments=departments)

# ----------------- Faculty Routes -----------------
@app.route('/faculty/dashboard')
@login_required
@role_required('faculty', 'admin')
def faculty_dashboard():
    """Faculty dashboard"""
    faculty_id = session['user_id']
    
    # Get faculty's coordinated events
    coordinated_events = Event.query.filter_by(
        faculty_coordinator_id=faculty_id
    ).order_by(Event.date.desc()).all()
    
    # Get event statistics
    event_stats = []
    for event in coordinated_events:
        reg_count = Registration.query.filter_by(event_id=event.id).count()
        event_stats.append({
            'event': event,
            'registrations': reg_count,
            'attendance_present': Registration.query.filter_by(
                event_id=event.id,
                attendance_status='Present'
            ).count(),
            'attendance_absent': Registration.query.filter_by(
                event_id=event.id,
                attendance_status='Absent'
            ).count()
        })
    
    # Get notifications
    notifications = Notification.query.filter_by(
        user_id=faculty_id,
        is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()
    
    return render_template('faculty/dashboard.html',
                         event_stats=event_stats,
                         notifications=notifications)

@app.route('/faculty/events/<int:event_id>/registrations')
@login_required
@role_required('faculty', 'admin')
def faculty_event_registrations(event_id):
    """Faculty view of event registrations"""
    event = Event.query.get_or_404(event_id)
    
    # Check if faculty is coordinator or admin
    if event.faculty_coordinator_id != session['user_id'] and session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('faculty_dashboard'))
    
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    return render_template('faculty/event_registrations.html',
                         event=event,
                         registrations=registrations)

# ----------------- Admin Routes -----------------
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    stats = get_dashboard_stats()
    
    # Recent activities
    recent_events = Event.query.order_by(Event.created_at.desc()).limit(5).all()
    recent_registrations = Registration.query.order_by(Registration.registered_at.desc()).limit(10).all()
    recent_announcements = Announcement.query.order_by(Announcement.published_date.desc()).limit(5).all()
    
    # System info
    system_info = {
        'total_users_today': User.query.filter(
            db.func.date(User.created_at) == datetime.now().date()
        ).count(),
        'total_registrations_today': Registration.query.filter(
            db.func.date(Registration.registered_at) == datetime.now().date()
        ).count(),
        'disk_usage': 'N/A'  # In production, calculate actual disk usage
    }
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_events=recent_events,
                         recent_registrations=recent_registrations,
                         recent_announcements=recent_announcements,
                         system_info=system_info)

@app.route('/admin/events', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_events():
    """Admin events management"""
    form = EventForm()
    form.category.choices = [(cat['id'], cat['name']) for cat in get_event_categories()]
    form.department_id.choices = [(0, 'Select Department')] + [
        (dept.id, f"{dept.name} ({dept.code})") 
        for dept in Department.query.order_by('name').all()
    ]
    form.faculty_coordinator_id.choices = [(0, 'Select Faculty')] + [
        (fac.id, f"{fac.name} ({fac.department.code if fac.department else 'No Dept'})")
        for fac in Faculty.query.filter_by(is_active=True).order_by('name').all()
    ]
    
    if form.validate_on_submit():
        event = Event(
            name=form.name.data,
            description=form.description.data,
            date=form.date.data,
            start_time=form.start_time.data.strftime('%H:%M') if form.start_time.data else None,
            end_time=form.end_time.data.strftime('%H:%M') if form.end_time.data else None,
            venue=form.venue.data,
            category=form.category.data,
            department_id=form.department_id.data if form.department_id.data != 0 else None,
            faculty_coordinator_id=form.faculty_coordinator_id.data if form.faculty_coordinator_id.data != 0 else None,
            capacity=form.capacity.data,
            is_active=form.is_active.data
        )
        
        db.session.add(event)
        db.session.commit()
        
        flash('Event created successfully!', 'success')
        logger.info(f'Event created: {event.name} by admin {session["user_id"]}')
        return redirect(url_for('admin_events'))
    
    events = Event.query.order_by(Event.date.desc()).all()
    
    return render_template('admin/events.html',
                         form=form,
                         events=events)

@app.route('/admin/event/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_event(event_id):
    """Edit event"""
    event = Event.query.get_or_404(event_id)
    
    form = EventForm(obj=event)
    form.category.choices = [(cat['id'], cat['name']) for cat in get_event_categories()]
    form.department_id.choices = [(0, 'Select Department')] + [
        (dept.id, f"{dept.name} ({dept.code})") 
        for dept in Department.query.order_by('name').all()
    ]
    form.faculty_coordinator_id.choices = [(0, 'Select Faculty')] + [
        (fac.id, f"{fac.name} ({fac.department.code if fac.department else 'No Dept'})")
        for fac in Faculty.query.filter_by(is_active=True).order_by('name').all()
    ]
    
    if form.validate_on_submit():
        event.name = form.name.data
        event.description = form.description.data
        event.date = form.date.data
        event.start_time = form.start_time.data.strftime('%H:%M') if form.start_time.data else None
        event.end_time = form.end_time.data.strftime('%H:%M') if form.end_time.data else None
        event.venue = form.venue.data
        event.category = form.category.data
        event.department_id = form.department_id.data if form.department_id.data != 0 else None
        event.faculty_coordinator_id = form.faculty_coordinator_id.data if form.faculty_coordinator_id.data != 0 else None
        event.capacity = form.capacity.data
        event.is_active = form.is_active.data
        event.updated_at = datetime.now()
        
        db.session.commit()
        
        flash('Event updated successfully!', 'success')
        logger.info(f'Event updated: {event.id} by admin {session["user_id"]}')
        return redirect(url_for('admin_events'))
    
    return render_template('admin/edit_event.html',
                         form=form,
                         event=event)

@app.route('/admin/event/<int:event_id>/registrations')
@login_required
@admin_required
def event_registrations(event_id):
    """Event registrations management"""
    event = Event.query.get_or_404(event_id)
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    # Statistics
    present_count = Registration.query.filter_by(
        event_id=event_id,
        attendance_status='Present'
    ).count()
    absent_count = Registration.query.filter_by(
        event_id=event_id,
        attendance_status='Absent'
    ).count()
    pending_count = Registration.query.filter_by(
        event_id=event_id,
        attendance_status='Registered'
    ).count()
    
    return render_template('admin/event_registrations.html',
                         event=event,
                         registrations=registrations,
                         present_count=present_count,
                         absent_count=absent_count,
                         pending_count=pending_count)

@app.route('/admin/export_registrations/<int:event_id>')
@login_required
@admin_required
def export_registrations(event_id):
    """Export registrations to CSV"""
    registrations = Registration.query.filter_by(event_id=event_id).all()
    event = Event.query.get_or_404(event_id)
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Name', 'Email', 'Registration No', 'Phone', 'Department',
        'Registered At', 'Attendance Status', 'Check-in Time', 'Check-out Time'
    ])
    
    # Write data
    for reg in registrations:
        writer.writerow([
            reg.user.name,
            reg.user.email,
            reg.user.registration_no or '',
            reg.user.phone or '',
            reg.user.department.name if reg.user.department else '',
            reg.registered_at.strftime('%Y-%m-%d %H:%M') if reg.registered_at else '',
            reg.attendance_status,
            reg.check_in_time.strftime('%Y-%m-%d %H:%M') if reg.check_in_time else '',
            reg.check_out_time.strftime('%Y-%m-%d %H:%M') if reg.check_out_time else ''
        ])
    
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'registrations_{event.name.replace(" ", "_")}_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/admin/announcements', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_announcements():
    """Announcements management"""
    form = AnnouncementForm()
    form.category.choices = [
        ('Academic', 'Academic'),
        ('Cultural', 'Cultural'),
        ('Sports', 'Sports'),
        ('Exam', 'Exam'),
        ('General', 'General'),
        ('Important', 'Important'),
        ('Urgent', 'Urgent')
    ]
    
    if form.validate_on_submit():
        expiry_date = datetime.now() + timedelta(days=form.expiry_days.data)
        
        announcement = Announcement(
            title=form.title.data,
            content=form.content.data,
            category=form.category.data,
            priority=form.priority.data,
            expiry_date=expiry_date
        )
        
        db.session.add(announcement)
        db.session.commit()
        
        flash('Announcement published successfully!', 'success')
        logger.info(f'Announcement created: {announcement.title}')
        return redirect(url_for('admin_announcements'))
    
    announcements = Announcement.query.order_by(Announcement.published_date.desc()).all()
    
    return render_template('admin/announcements.html',
                         form=form,
                         announcements=announcements)

@app.route('/admin/departments', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_departments():
    """Departments management"""
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        description = request.form.get('description', '')
        
        if Department.query.filter_by(code=code).first():
            flash('Department code already exists', 'warning')
        else:
            department = Department(
                name=name,
                code=code,
                description=description
            )
            db.session.add(department)
            db.session.commit()
            flash('Department added successfully!', 'success')
        
        return redirect(url_for('admin_departments'))
    
    departments = Department.query.all()
    return render_template('admin/departments.html', departments=departments)

@app.route('/admin/faculty', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_faculty():
    """Faculty management"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        department_id = request.form.get('department_id')
        designation = request.form.get('designation', '')
        phone = request.form.get('phone', '')
        
        # Check if email exists
        if Faculty.query.filter_by(email=email).first():
            flash('Faculty with this email already exists', 'warning')
            return redirect(url_for('admin_faculty'))
        
        # Create faculty record
        faculty = Faculty(
            name=name,
            email=email,
            department_id=department_id if department_id else None,
            designation=designation,
            phone=phone
        )
        
        # Also create user account if not exists
        if not User.query.filter_by(email=email).first():
            user = User(
                name=name,
                email=email,
                password=generate_password_hash('faculty123'),  # Default password
                role='faculty',
                department_id=department_id if department_id else None,
                phone=phone
            )
            db.session.add(user)
        
        db.session.add(faculty)
        db.session.commit()
        
        flash('Faculty member added successfully!', 'success')
        logger.info(f'Faculty added: {name}')
        return redirect(url_for('admin_faculty'))
    
    faculty = Faculty.query.all()
    departments = Department.query.all()
    
    return render_template('admin/faculty.html',
                         faculty=faculty,
                         departments=departments)

@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    """Analytics dashboard"""
    stats = get_dashboard_stats()
    
    # Event growth over time (last 12 months)
    twelve_months_ago = datetime.now() - timedelta(days=365)
    events_by_month = db.session.query(
        db.func.strftime('%Y-%m', Event.created_at).label('month'),
        db.func.count(Event.id).label('count')
    ).filter(Event.created_at >= twelve_months_ago)\
     .group_by('month').order_by('month').all()
    
    # Department participation
    dept_participation = db.session.query(
        Department.name,
        db.func.count(Registration.id).label('registrations')
    ).join(Event, Event.department_id == Department.id, isouter=True)\
     .join(Registration, Registration.event_id == Event.id, isouter=True)\
     .group_by(Department.name).all()
    
    # Category distribution
    category_dist = db.session.query(
        Event.category,
        db.func.count(Event.id).label('count')
    ).group_by(Event.category).all()
    
    # User registration trend (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    users_by_day = db.session.query(
        db.func.date(User.created_at).label('date'),
        db.func.count(User.id).label('count')
    ).filter(User.created_at >= thirty_days_ago)\
     .group_by('date').order_by('date').all()
    
    return render_template('admin/analytics.html',
                         stats=stats,
                         events_by_month=events_by_month,
                         dept_participation=dept_participation,
                         category_dist=category_dist,
                         users_by_day=users_by_day)

# ----------------- Chatbot -----------------
@app.route('/chatbot', methods=['POST'])
@limiter.limit("20 per minute")
def chatbot():
    """Chatbot endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'response': 'Please provide a message'}), 400
        
        message = data.get('message', '').lower().strip()
        user_id = data.get('user_id')
        
        # Enhanced responses based on context
        responses = {
            'hello': "Hello! 👋 Welcome to Central University of Karnataka Events Hub. How can I help you today?",
            'hi': "Hi there! I'm your university event assistant. What can I do for you?",
            'event': "You can browse all events at the Events page. Use filters to find specific events by category or department.",
            'register': "To register for events, first login with your university credentials. Then visit any event page and click 'Register Now'.",
            'login': "Go to the Login page and use your university email (@cuk.ac.in). Forgot password? Contact admin@cuk.ac.in",
            'password': "For password reset, please contact the system administrator at admin@cuk.ac.in or call 08388-251100",
            'department': "We have multiple departments including Computer Science, Mathematics, Physics, and more. Check the events page for department-specific events.",
            'calendar': "View the event calendar to see all upcoming events in a monthly view. You can click on events for details.",
            'contact': "For queries, contact:\n📧 events@cuk.ac.in\n📞 08388-251100\n📍 Admin Block, CUK Campus",
            'help': "I can help you with:\n• Event information and registration\n• Department-wise event listings\n• Event calendar view\n• Contact information\n• System navigation\n\nTry asking specific questions!",
            'upcoming': "Check the Events page or Calendar for upcoming events. You can filter by category or department.",
            'feedback': "You can submit feedback on completed events. Visit the event page and click 'Submit Feedback'.",
            'certificate': "Certificates are issued for completed events. Contact the event coordinator for certificate details.",
            'profile': "Update your profile information from the dashboard. You can change your password and contact details there.",
            'admin': "Admin features include event management, user management, announcements, and analytics. Requires admin login."
        }
        
        # Check for keywords in message
        response = "I'm here to help with campus events! Try asking about events, registration, departments, or contact information."
        
        for key, reply in responses.items():
            if key in message:
                response = reply
                break
        
        # Log chatbot interaction
        logger.info(f'Chatbot: User {user_id} asked: {message}')
        
        return jsonify({'response': response, 'timestamp': datetime.now().isoformat()})
        
    except Exception as e:
        logger.error(f'Chatbot error: {str(e)}')
        return jsonify({'response': 'Sorry, I encountered an error. Please try again later.'}), 500

# ----------------- File Upload Routes -----------------
@app.route('/upload/<path:filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def save_uploaded_file(file, folder='images'):
    """Save uploaded file and return path"""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, unique_filename)
        
        # Create folder if not exists
        os.makedirs(os.dirname(save_path), exist_ok=True)
        
        file.save(save_path)
        return f'/upload/{folder}/{unique_filename}'
    return None

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
