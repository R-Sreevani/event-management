from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
from functools import wraps
import csv
from io import StringIO

app = Flask(__name__)
app.secret_key = 'cuk-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cuk_events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ✅ Inject current datetime object into all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# ----------------- Models -----------------
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    code = db.Column(db.String(10))
    description = db.Column(db.Text)
    
class Faculty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    designation = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    
    department = db.relationship('Department', backref='faculty')
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(10))  # 'admin', 'student', 'faculty'
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    registration_no = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    
    department = db.relationship('Department', backref='users')
    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10))
    end_time = db.Column(db.String(10))
    venue = db.Column(db.String(200))
    category = db.Column(db.String(50))  # 'academic', 'cultural', 'sports', 'workshop', 'seminar'
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    faculty_coordinator_id = db.Column(db.Integer, db.ForeignKey('faculty.id'))
    capacity = db.Column(db.Integer, default=100)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    department = db.relationship('Department', backref='events')
    faculty_coordinator = db.relationship('Faculty', backref='coordinated_events')
    
class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.now)
    attendance_status = db.Column(db.String(20), default='Registered')  # 'Registered', 'Present', 'Absent'
    
    user = db.relationship('User', backref='registrations')
    event = db.relationship('Event', backref='registrations')
    
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    category = db.Column(db.String(50))  # 'Academic', 'Cultural', 'Sports', 'Exam', 'General'
    priority = db.Column(db.String(20))  # 'High', 'Medium', 'Low'
    published_date = db.Column(db.DateTime, default=datetime.now)
    expiry_date = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rating = db.Column(db.Integer)  # 1-5
    comment = db.Column(db.Text)
    submitted_date = db.Column(db.DateTime, default=datetime.now)
    
    event = db.relationship('Event', backref='feedbacks')
    user = db.relationship('User', backref='feedbacks')
    
class EventGallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'))
    image_url = db.Column(db.String(500))
    caption = db.Column(db.String(200))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    upload_date = db.Column(db.DateTime, default=datetime.now)

# ----------------- Decorators -----------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def faculty_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['admin', 'faculty']:
            flash('Faculty access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ----------------- Utility Functions -----------------
def get_event_categories():
    return [
        {'id': 'academic', 'name': '🎓 Academic', 'icon': 'graduation-cap'},
        {'id': 'cultural', 'name': '🎭 Cultural', 'icon': 'mask'},
        {'id': 'sports', 'name': '⚽ Sports', 'icon': 'futbol'},
        {'id': 'workshop', 'name': '🔧 Workshop', 'icon': 'tools'},
        {'id': 'seminar', 'name': '🎤 Seminar', 'icon': 'chalkboard-teacher'},
        {'id': 'conference', 'name': '🏛️ Conference', 'icon': 'users'},
        {'id': 'competition', 'name': '🏆 Competition', 'icon': 'trophy'},
        {'id': 'others', 'name': '📌 Others', 'icon': 'star'}
    ]

def get_dashboard_stats():
    stats = {
        'total_events': Event.query.filter_by(is_active=True).count(),
        'upcoming_events': Event.query.filter(
            Event.date >= datetime.now().date(),
            Event.is_active == True
        ).count(),
        'total_registrations': Registration.query.count(),
        'total_users': User.query.count(),
        'total_departments': Department.query.count(),
        'total_faculty': Faculty.query.count()
    }
    
    # Department-wise event count
    dept_stats = db.session.query(
        Department.name,
        db.func.count(Event.id)
    ).join(Event).group_by(Department.name).all()
    
    stats['department_stats'] = dept_stats
    
    return stats

# ----------------- Routes -----------------
@app.route('/')
def index():
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

@app.route('/events')
def events():
    category = request.args.get('category', 'all')
    department = request.args.get('department', 'all')
    search = request.args.get('search', '')
    
    query = Event.query.filter_by(is_active=True)
    
    if category != 'all':
        query = query.filter_by(category=category)
    
    if department != 'all':
        query = query.filter_by(department_id=department)
    
    if search:
        query = query.filter(Event.name.ilike(f'%{search}%'))
    
    events = query.order_by(Event.date).all()
    departments = Department.query.all()
    categories = get_event_categories()
    
    return render_template('events.html',
                         events=events,
                         departments=departments,
                         categories=categories,
                         selected_category=category,
                         selected_department=department)

@app.route('/calendar')
def calendar():
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
            'end': event.date.isoformat(),
            'color': color_map.get(event.category, '#0077cc'),
            'url': url_for('event_detail', event_id=event.id)
        })
    
    return render_template('calendar.html', events=calendar_events)

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    is_registered = False
    user_feedback = None
    
    if 'user_id' in session:
        is_registered = Registration.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first() is not None
        
        user_feedback = Feedback.query.filter_by(
            user_id=session['user_id'],
            event_id=event_id
        ).first()
    
    # Calculate average rating
    avg_rating = db.session.query(db.func.avg(Feedback.rating)).filter_by(event_id=event_id).scalar()
    avg_rating = round(avg_rating, 1) if avg_rating else 0
    
    # Get feedbacks
    feedbacks = Feedback.query.filter_by(event_id=event_id).order_by(Feedback.submitted_date.desc()).limit(10).all()
    
    # Get gallery images
    gallery = EventGallery.query.filter_by(event_id=event_id).all()
    
    return render_template('event_detail.html',
                         event=event,
                         is_registered=is_registered,
                         user_feedback=user_feedback,
                         avg_rating=avg_rating,
                         feedbacks=feedbacks,
                         gallery=gallery)

@app.route('/register_event/<int:event_id>')
@login_required
def register_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check capacity
    registrations_count = Registration.query.filter_by(event_id=event_id).count()
    if registrations_count >= event.capacity:
        flash('Event is full!', 'warning')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Check if already registered
    existing = Registration.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if existing:
        flash('Already registered for this event!', 'info')
    else:
        registration = Registration(
            user_id=session['user_id'],
            event_id=event_id
        )
        db.session.add(registration)
        db.session.commit()
        flash('Successfully registered for the event!', 'success')
    
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/unregister_event/<int:event_id>')
@login_required
def unregister_event(event_id):
    registration = Registration.query.filter_by(
        user_id=session['user_id'],
        event_id=event_id
    ).first()
    
    if registration:
        db.session.delete(registration)
        db.session.commit()
        flash('Successfully unregistered from the event', 'info')
    
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/submit_feedback/<int:event_id>', methods=['POST'])
@login_required
def submit_feedback(event_id):
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    
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
    else:
        feedback = Feedback(
            user_id=session['user_id'],
            event_id=event_id,
            rating=rating,
            comment=comment
        )
        db.session.add(feedback)
    
    db.session.commit()
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('event_detail', event_id=event_id))

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
            session['department_id'] = user.department_id
            
            flash(f'Welcome back, {user.name}!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'faculty':
                return redirect(url_for('faculty_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        
        flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = 'student'  # Default role
        registration_no = request.form.get('registration_no', '')
        phone = request.form.get('phone', '')
        department_id = request.form.get('department_id')
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register_user'))
        
        # Verify university email (optional)
        if not email.endswith('@cuk.ac.in'):
            flash('Please use your university email (@cuk.ac.in)', 'info')
        
        user = User(
            name=name,
            email=email,
            password=password,
            role=role,
            registration_no=registration_no,
            phone=phone,
            department_id=department_id if department_id else None
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    departments = Department.query.all()
    return render_template('auth/register.html', departments=departments)

@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out!', 'info')
    return redirect(url_for('index'))

# ----------------- Student Dashboard -----------------
@app.route('/student/dashboard')
@login_required
def student_dashboard():
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
    
    return render_template('student/dashboard.html',
                         registered_events=registered_events,
                         department_events=department_events,
                         announcements=announcements)

# ----------------- Faculty Dashboard -----------------
@app.route('/faculty/dashboard')
@faculty_required
def faculty_dashboard():
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
            'attendance': Registration.query.filter_by(
                event_id=event.id,
                attendance_status='Present'
            ).count()
        })
    
    return render_template('faculty/dashboard.html',
                         event_stats=event_stats)

# ----------------- Admin Dashboard -----------------
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    stats = get_dashboard_stats()
    
    # Recent activities
    recent_events = Event.query.order_by(Event.created_at.desc()).limit(5).all()
    recent_registrations = Registration.query.order_by(Registration.registered_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_events=recent_events,
                         recent_registrations=recent_registrations)

@app.route('/admin/events', methods=['GET', 'POST'])
@admin_required
def admin_events():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        venue = request.form['venue']
        category = request.form['category']
        department_id = request.form.get('department_id')
        faculty_coordinator_id = request.form.get('faculty_coordinator_id')
        capacity = request.form.get('capacity', 100)
        
        event = Event(
            name=name,
            description=description,
            date=date,
            start_time=start_time,
            end_time=end_time,
            venue=venue,
            category=category,
            department_id=department_id if department_id else None,
            faculty_coordinator_id=faculty_coordinator_id if faculty_coordinator_id else None,
            capacity=capacity
        )
        
        db.session.add(event)
        db.session.commit()
        
        flash('Event created successfully!', 'success')
        return redirect(url_for('admin_events'))
    
    events = Event.query.order_by(Event.date.desc()).all()
    departments = Department.query.all()
    faculty = Faculty.query.all()
    categories = get_event_categories()
    
    return render_template('admin/events.html',
                         events=events,
                         departments=departments,
                         faculty=faculty,
                         categories=categories)

@app.route('/admin/event/<int:event_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    if request.method == 'POST':
        event.name = request.form['name']
        event.description = request.form['description']
        event.date = datetime.strptime(request.form['date'], '%Y-%m-%d').date()
        event.start_time = request.form.get('start_time')
        event.end_time = request.form.get('end_time')
        event.venue = request.form['venue']
        event.category = request.form['category']
        event.department_id = request.form.get('department_id')
        event.faculty_coordinator_id = request.form.get('faculty_coordinator_id')
        event.capacity = request.form.get('capacity', 100)
        event.is_active = 'is_active' in request.form
        
        db.session.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('admin_events'))
    
    departments = Department.query.all()
    faculty = Faculty.query.all()
    categories = get_event_categories()
    
    return render_template('admin/edit_event.html',
                         event=event,
                         departments=departments,
                         faculty=faculty,
                         categories=categories)

@app.route('/admin/event/<int:event_id>/registrations')
@admin_required
def event_registrations(event_id):
    event = Event.query.get_or_404(event_id)
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    return render_template('admin/event_registrations.html',
                         event=event,
                         registrations=registrations)

@app.route('/admin/export_registrations/<int:event_id>')
@admin_required
def export_registrations(event_id):
    registrations = Registration.query.filter_by(event_id=event_id).all()
    
    # Create CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Name', 'Email', 'Registration No', 'Phone', 'Registered At', 'Attendance Status'])
    
    # Write data
    for reg in registrations:
        writer.writerow([
            reg.user.name,
            reg.user.email,
            reg.user.registration_no or '',
            reg.user.phone or '',
            reg.registered_at.strftime('%Y-%m-%d %H:%M'),
            reg.attendance_status
        ])
    
    output.seek(0)
    
    return send_file(
        StringIO(output.getvalue()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'registrations_event_{event_id}.csv'
    )

@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        priority = request.form['priority']
        expiry_days = int(request.form.get('expiry_days', 7))
        
        expiry_date = datetime.now() + timedelta(days=expiry_days)
        
        announcement = Announcement(
            title=title,
            content=content,
            category=category,
            priority=priority,
            expiry_date=expiry_date
        )
        
        db.session.add(announcement)
        db.session.commit()
        
        flash('Announcement published successfully!', 'success')
        return redirect(url_for('admin_announcements'))
    
    announcements = Announcement.query.order_by(Announcement.published_date.desc()).all()
    
    return render_template('admin/announcements.html', announcements=announcements)

@app.route('/admin/departments', methods=['GET', 'POST'])
@admin_required
def admin_departments():
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        description = request.form.get('description', '')
        
        department = Department(name=name, code=code, description=description)
        db.session.add(department)
        db.session.commit()
        
        flash('Department added successfully!', 'success')
        return redirect(url_for('admin_departments'))
    
    departments = Department.query.all()
    return render_template('admin/departments.html', departments=departments)

@app.route('/admin/faculty', methods=['GET', 'POST'])
@admin_required
def admin_faculty():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        department_id = request.form.get('department_id')
        designation = request.form.get('designation', '')
        phone = request.form.get('phone', '')
        
        # Also create user account for faculty
        user = User(
            name=name,
            email=email,
            password=generate_password_hash('faculty123'),  # Default password
            role='faculty',
            department_id=department_id,
            phone=phone
        )
        
        faculty = Faculty(
            name=name,
            email=email,
            department_id=department_id,
            designation=designation,
            phone=phone
        )
        
        db.session.add(user)
        db.session.add(faculty)
        db.session.commit()
        
        flash('Faculty member added successfully!', 'success')
        return redirect(url_for('admin_faculty'))
    
    faculty = Faculty.query.all()
    departments = Department.query.all()
    
    return render_template('admin/faculty.html',
                         faculty=faculty,
                         departments=departments)

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    stats = get_dashboard_stats()
    
    # Event growth over time
    events_by_month = db.session.query(
        db.func.strftime('%Y-%m', Event.created_at).label('month'),
        db.func.count(Event.id).label('count')
    ).group_by('month').order_by('month').all()
    
    # Department participation
    dept_participation = db.session.query(
        Department.name,
        db.func.count(Registration.id).label('registrations')
    ).join(Event, Event.department_id == Department.id)\
     .join(Registration, Registration.event_id == Event.id)\
     .group_by(Department.name).all()
    
    # Category distribution
    category_dist = db.session.query(
        Event.category,
        db.func.count(Event.id).label('count')
    ).group_by(Event.category).all()
    
    return render_template('admin/analytics.html',
                         stats=stats,
                         events_by_month=events_by_month,
                         dept_participation=dept_participation,
                         category_dist=category_dist)

# ----------------- Chatbot -----------------
@app.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.get_json()
    message = data.get('message', '').lower()
    
    responses = {
        'hello': "Hello! 👋 Welcome to Central University of Karnataka Events Hub. How can I help you?",
        'hi': "Hi there! I'm your university event assistant.",
        'event': "You can browse all events at /events. Use filters to find specific events.",
        'register': "To register for events, first login with your university credentials.",
        'login': "Go to /login and use your university email. Forgot password? Contact admin.",
        'password': "For password reset, please contact the system administrator at admin@cuk.ac.in",
        'department': "We have multiple departments including CS, Mathematics, Physics, etc. Check /events for department-specific events.",
        'calendar': "View the event calendar at /calendar to see all upcoming events.",
        'contact': "For queries, contact:\n📧 events@cuk.ac.in\n📞 08388-251100",
        'help': "I can help with:\n• Event information\n• Registration process\n• Department events\n• Calendar view\n• Contact details"
    }
    
    response = "I can help you with events, registration, and university information. Try asking about 'events', 'calendar', or 'departments'."
    
    for key in responses:
        if key in message:
            response = responses[key]
            break
    
    return jsonify({'response': response})

# ----------------- Error Handlers -----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# ----------------- Initialize Database -----------------
def initialize_database():
    with app.app_context():
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

if __name__ == '__main__':
    initialize_database()
    print("🚀 Server starting at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
