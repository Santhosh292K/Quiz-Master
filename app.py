from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# User Model
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

# Quiz Model
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)

# Current User Helper
def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# Template Context Processor
@app.context_processor
def utility_processor():
    return dict(current_user=get_current_user())

# Decorators
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

# Helper Functions
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

        try:
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
    return render_template('user_dashboard.html', user=user, active_page='dashboard')

@app.route('/quiz')
@login_required
def quiz():
    return render_template('quiz.html', active_page='quiz')

@app.route('/summary')
@login_required
def summary():
    user = get_current_user()
    quiz_results = Quiz.query.filter_by(user_id=user.id).order_by(Quiz.date_taken.desc()).all()
    return render_template('summary.html', active_page='summary', quiz_results=quiz_results)

@app.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html', active_page='dashboard')

@app.route('/admin/users')
@admin_required
def users():
    all_users = User.query.filter(User.id != session['user_id']).all()
    return render_template('admin_users_data.html', active_page='users', users=all_users)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# User Profile Management
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
            flash('Error updating profile. Please try again.', 'error')
    return render_template('edit_profile.html', user=user)

# Admin User Management
@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('Cannot delete admin user.', 'error')
    return redirect(url_for('users'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_account()
    app.run(debug=True)