from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.email}>'

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    chapters = db.relationship('Chapter', backref='subject', lazy=True, cascade="all, delete-orphan")

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)

# Helpers and Decorators
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

@app.context_processor
def utility_processor():
    return dict(current_user=get_current_user())

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def create_admin_account():
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        admin_password = 'Admin@123'
        hashed_password = generate_password_hash(admin_password)
        admin_user = User(
            email='admin@example.com',
            password=hashed_password,
            full_name='Admin User',
            qualification='System Administrator',
            dob=datetime.strptime('2000-01-01', '%Y-%m-%d').date(),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print('Admin account created successfully')
    else:
        print('Admin account already exists')

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            qualification = request.form.get('qualification')
            dob = request.form.get('dob')

            if not validate_email(email):
                flash('Invalid email format.', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('register'))

            dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
            hashed_password = generate_password_hash(password)
            new_user = User(
                email=email,
                password=hashed_password,
                full_name=full_name,
                qualification=qualification,
                dob=dob_date,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    if user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    subjects = Subject.query.order_by(Subject.created_at.desc()).all()
    return render_template('admin_dashboard.html', active_page='home', subjects=subjects)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    subjects = Subject.query.order_by(Subject.created_at.desc()).all()
    return render_template('user_dashboard.html', active_page='home', subjects=subjects)

# Admin Subject Management Routes
@app.route('/admin/subject/add', methods=['GET', 'POST'])
@admin_required
def add_subject():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            
            if not name:
                flash('Subject name is required', 'error')
                return redirect(url_for('admin_dashboard'))
            
            new_subject = Subject(name=name, description=description)
            db.session.add(new_subject)
            db.session.commit()
            flash('Subject added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error adding subject. Please try again.', 'error')
            print(f"Error adding subject: {str(e)}")
            
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subject/<int:subject_id>/edit', methods=['POST'])
@admin_required
def edit_subject(subject_id):
    try:
        subject = Subject.query.get_or_404(subject_id)
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Subject name is required', 'error')
            return redirect(url_for('admin_dashboard'))
        
        subject.name = name
        subject.description = description
        db.session.commit()
        flash('Subject updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating subject. Please try again.', 'error')
        print(f"Error updating subject: {str(e)}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subject/<int:subject_id>/delete', methods=['POST'])
@admin_required
def delete_subject(subject_id):
    try:
        subject = Subject.query.get_or_404(subject_id)
        db.session.delete(subject)
        db.session.commit()
        flash('Subject deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting subject. Please try again.', 'error')
        print(f"Error deleting subject: {str(e)}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subject/<int:subject_id>/chapter/add', methods=['POST'])
@admin_required
def add_chapter(subject_id):
    try:
        subject = Subject.query.get_or_404(subject_id)
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Chapter name is required', 'error')
            return redirect(url_for('admin_dashboard'))
        
        new_chapter = Chapter(
            name=name,
            description=description,
            subject_id=subject_id
        )
        db.session.add(new_chapter)
        db.session.commit()
        flash('Chapter added successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error adding chapter. Please try again.', 'error')
        print(f"Error adding chapter: {str(e)}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/chapter/<int:chapter_id>/edit', methods=['POST'])
@admin_required
def edit_chapter(chapter_id):
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        name = request.form.get('name')
        description = request.form.get('description')
        
        if not name:
            flash('Chapter name is required', 'error')
            return redirect(url_for('admin_dashboard'))
        
        chapter.name = name
        chapter.description = description
        db.session.commit()
        flash('Chapter updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating chapter. Please try again.', 'error')
        print(f"Error updating chapter: {str(e)}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/chapter/<int:chapter_id>/delete', methods=['POST'])
@admin_required
def delete_chapter(chapter_id):
    try:
        chapter = Chapter.query.get_or_404(chapter_id)
        db.session.delete(chapter)
        db.session.commit()
        flash('Chapter deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting chapter. Please try again.', 'error')
        print(f"Error deleting chapter: {str(e)}")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/subject/<int:subject_id>/chapters')
@admin_required
def get_subject_chapters(subject_id):
    try:
        chapters = Chapter.query.filter_by(subject_id=subject_id).all()
        return jsonify([{
            'id': chapter.id,
            'name': chapter.name
        } for chapter in chapters])
    except Exception as e:
        return jsonify({'error': 'Error fetching chapters'}), 500

@app.route('/admin_quiz')
@login_required
def admin_quiz():
    subjects = Subject.query.all()
    return render_template('admin_quiz.html', active_page='quiz', subjects=subjects)

@app.route('/summary')
@login_required
def summary():
    user = get_current_user()
    quiz_results = Quiz.query.filter_by(user_id=user.id).order_by(Quiz.date_taken.desc()).all()
    return render_template('summary.html', active_page='summary', quiz_results=quiz_results)

@app.route('/users')
@admin_required
def users():
    try:
        all_users = User.query.filter(User.id != session['user_id']).all()
        return render_template('users.html', active_page='users', users=all_users)
    except Exception as e:
        flash('Error loading users. Please try again.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = get_current_user()
    if request.method == 'POST':
        try:
            user.full_name = request.form.get('full_name')
            user.qualification = request.form.get('qualification')
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'error')
            print(f"Error updating profile: {str(e)}")
    return render_template('edit_profile.html', user=user)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if not user.is_admin:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.', 'success')
        else:
            flash('Cannot delete admin user.', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user. Please try again.', 'error')
        print(f"Error deleting user: {str(e)}")
        
    return redirect(url_for('users'))


@app.route('/admin/quiz/create', methods=['POST'])
@admin_required
def create_quiz():
    try:
        data = request.get_json()
        # Add your database logic here to save the quiz
        return jsonify({'message': 'Quiz created successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_account()
    app.run(debug=True)