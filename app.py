from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
from datetime import datetime
from datetime import datetime, timedelta
from sqlalchemy import func


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
    quiz_attempts = db.relationship('QuizAttempt', backref='user', lazy=True)

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
    quiz_id = db.Column(db.String(50), unique=True, nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade="all, delete-orphan")
    attempts = db.relationship('QuizAttempt', backref='quiz', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'quiz_id': self.quiz_id,
            'subject_id': self.subject_id,
            'chapter_id': self.chapter_id,
            'date': self.date.isoformat(),
            'duration': self.duration,
            'questions': [question.to_dict() for question in self.questions]
        }
    

# Add the explanation field to the Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    options = db.relationship('Option', backref='question', lazy=True, cascade="all, delete-orphan")
    correct_option_index = db.Column(db.Integer, nullable=False)
    explanation = db.Column(db.Text, nullable=False)  # New field for answer explanation
    
    def to_dict(self):
        return {
            'id': self.id,
            'question_text': self.question_text,
            'options': [option.to_dict() for option in self.options],
            'correct_option_index': self.correct_option_index,
            'explanation': self.explanation
        }


class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    option_text = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'option_text': self.option_text
        }
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
    return render_template('admin/admin_dashboard.html', active_page='home', subjects=subjects)

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    subjects = Subject.query.order_by(Subject.created_at.desc()).all()
    return render_template('user/user_dashboard.html', active_page='home', subjects=subjects)

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
    return render_template('admin/admin_quiz.html', active_page='quiz', subjects=subjects)

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
        return render_template('admin/users.html', active_page='users', users=all_users)
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


# Add these new routes to your Flask application

@app.route('/admin/subjects', methods=['GET'])
@admin_required
def get_subjects():
    try:
        subjects = Subject.query.all()
        return jsonify([{
            'id': subject.id,
            'name': subject.name
        } for subject in subjects])
    except Exception as e:
        print(f"Error fetching subjects: {str(e)}")
        return jsonify({'error': 'Failed to fetch subjects'}), 500

@app.route('/admin/subjects/<int:subject_id>/chapters', methods=['GET'])
@admin_required
def get_chapters(subject_id):
    try:
        chapters = Chapter.query.filter_by(subject_id=subject_id).all()
        return jsonify([{
            'id': chapter.id,
            'name': chapter.name
        } for chapter in chapters])
    except Exception as e:
        print(f"Error fetching chapters: {str(e)}")
        return jsonify({'error': 'Failed to fetch chapters'}), 500

@app.route('/admin/quizzes', methods=['GET'])
@admin_required
def get_quizzes():
    try:
        quizzes = Quiz.query.order_by(Quiz.created_at.desc()).all()
        return jsonify([{
            'id': quiz.id,
            'quiz_id': quiz.quiz_id,
            'subject_id': quiz.subject_id,
            'chapter_id': quiz.chapter_id,
            'date': quiz.date.isoformat(),
            'duration': quiz.duration,
            'questions': [{
                'question_text': question.question_text,
                'options': [{
                    'id': option.id,
                    'option_text': option.option_text
                } for option in question.options],
                'correct_option_index': question.correct_option_index,
                'explanation': question.explanation
            } for question in quiz.questions]
        } for quiz in quizzes]), 200
    except Exception as e:
        print(f"Error fetching quizzes: {str(e)}")
        return jsonify({'error': 'Failed to fetch quizzes'}), 500

@app.route('/admin/quizzes', methods=['POST'])
@admin_required
def create_quiz():
    try:
        data = request.get_json()
        
        # Create new quiz record
        new_quiz = Quiz(
            quiz_id=data['title'],  
            subject_id=int(data['subject_id']),
            chapter_id=int(data['chapter_id']),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            duration=int(data['duration'])
        )
        db.session.add(new_quiz)
        db.session.flush()
        
        # Create questions for the quiz
        for q_data in data['questions']:
            question = Question(
                quiz_id=new_quiz.id,
                question_text=q_data['question_text'],
                correct_option_index=q_data['correct_option_index'],
                explanation=q_data['explanation']
            )
            db.session.add(question)
            db.session.flush()
            
            # Create options for each question
            for option in q_data['options']:
                opt = Option(
                    question_id=question.id,
                    option_text=option['option_text']
                )
                db.session.add(opt)
        
        db.session.commit()
        return jsonify({'message': 'Quiz created successfully', 'quiz_id': new_quiz.id}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error creating quiz: {str(e)}")
        return jsonify({'error': 'Failed to create quiz'}), 500
    
@app.route('/admin/quiz/<int:quiz_id>', methods=['PUT'])
@admin_required
def update_quiz(quiz_id):
    try:
        data = request.get_json()
        quiz = Quiz.query.get_or_404(quiz_id)
        
        # Update quiz details
        quiz.quiz_id = data['title']  # Changed from quiz_id to title to match frontend
        quiz.subject_id = int(data['subject_id'])
        quiz.chapter_id = int(data['chapter_id'])
        quiz.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        quiz.duration = int(data['duration'])
        
        # Delete existing questions and options
        for question in quiz.questions:
            db.session.delete(question)
        
        # Create new questions and options
        for q_data in data['questions']:
            question = Question(
                quiz_id=quiz.id,
                question_text=q_data['question_text'],
                correct_option_index=q_data['correct_option_index'],
                explanation=q_data['explanation']
            )
            db.session.add(question)
            db.session.flush()
            
            # Fix: properly handle options structure
            for option in q_data['options']:
                opt = Option(
                    question_id=question.id,
                    option_text=option['option_text']
                )
                db.session.add(opt)
        
        db.session.commit()
        return jsonify({'message': 'Quiz updated successfully', 'quiz': quiz.to_dict()}), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Error updating quiz: {str(e)}")
        return jsonify({'error': 'Failed to update quiz'}), 500
    

@app.route('/admin/quiz/<int:quiz_id>', methods=['GET'])
@admin_required
def get_quiz(quiz_id):
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        return jsonify(quiz.to_dict()), 200
    except Exception as e:
        print(f"Error fetching quiz: {str(e)}")
        return jsonify({'error': 'Failed to fetch quiz'}), 500



@app.route('/admin/quiz/<int:quiz_id>', methods=['DELETE'])
@admin_required
def delete_quiz(quiz_id):
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        db.session.delete(quiz)
        db.session.commit()
        return jsonify({'message': 'Quiz deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting quiz: {str(e)}")
        return jsonify({'error': 'Failed to delete quiz'}), 500

@app.route('/admin/user/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            qualification = request.form.get('qualification')
            dob = request.form.get('dob')

            if not validate_email(email):
                flash('Invalid email format.', 'error')
                return redirect(url_for('users'))

            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('users'))

            dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
            hashed_password = generate_password_hash(password)
            new_user = User(
                email=email,
                password=hashed_password,
                full_name=full_name,
                qualification=qualification,
                dob=dob_date,
                is_admin=False  # Regular user by default
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('users'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding user. Please try again.', 'error')
            print(f"Error adding user: {str(e)}")
            return redirect(url_for('users'))
    return redirect(url_for('users'))

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent editing admin users
    if user.is_admin and user.id != session['user_id']:
        flash('Cannot edit admin user.', 'error')
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            full_name = request.form.get('full_name')
            qualification = request.form.get('qualification')
            dob = request.form.get('dob')
            
            # Validate email format
            if not validate_email(email):
                flash('Invalid email format.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            # Check if email is taken by another user
            existing_user = User.query.filter(User.email == email, User.id != user_id).first()
            if existing_user:
                flash('Email already registered to another user.', 'error')
                return redirect(url_for('edit_user', user_id=user_id))
            
            # Update user details
            user.email = email
            user.full_name = full_name
            user.qualification = qualification
            user.dob = datetime.strptime(dob, '%Y-%m-%d').date()
            
            # Update password if provided
            password = request.form.get('password')
            if password and password.strip():
                user.password = generate_password_hash(password)
            
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
            return redirect(url_for('edit_user', user_id=user_id))
    
    # GET request - display edit form
    return render_template('admin/edit_user.html', user=user, active_page='users')

@app.route('/admin/summary')
@admin_required
def admin_summary():
    # Count statistics
    total_subjects = Subject.query.count()
    total_chapters = Chapter.query.count()
    total_quizzes = Quiz.query.count()
    total_users = User.query.filter(User.is_admin == False).count()
    total_questions = Question.query.count()
    
    # Subject-wise chapter count
    subjects = Subject.query.all()
    subject_data = []
    for subject in subjects:
        chapter_count = Chapter.query.filter_by(subject_id=subject.id).count()
        quiz_count = Quiz.query.filter_by(subject_id=subject.id).count()
        subject_data.append({
            'id': subject.id,
            'name': subject.name,
            'chapter_count': chapter_count,
            'quiz_count': quiz_count
        })
    
    # Monthly quiz creation data (for the past year)
    quiz_monthly_data = []
    current_date = datetime.utcnow()
    for i in range(12):
        month_date = current_date - timedelta(days=30 * i)
        month_start = datetime(month_date.year, month_date.month, 1)
        if month_date.month == 12:
            next_month = datetime(month_date.year + 1, 1, 1)
        else:
            next_month = datetime(month_date.year, month_date.month + 1, 1)
        month_quiz_count = Quiz.query.filter(
            Quiz.created_at >= month_start,
            Quiz.created_at < next_month
        ).count()
        quiz_monthly_data.append({
            'month': month_start.strftime('%b %Y'),
            'count': month_quiz_count
        })
    quiz_monthly_data.reverse()
    
    # Chapters by subject (for pie chart)
    chapters_by_subject = []
    for subject in subjects:
        count = Chapter.query.filter_by(subject_id=subject.id).count()
        if count > 0:
            chapters_by_subject.append({
                'name': subject.name,
                'count': count
            })
    
    # Most active chapters (most quizzes)
    active_chapters_query = db.session.query(
        Chapter.id, 
        Chapter.name, 
        Subject.name.label('subject_name'),
        db.func.count(Quiz.id).label('quiz_count')
    ).join(Quiz, Quiz.chapter_id == Chapter.id
    ).join(Subject, Subject.id == Chapter.subject_id
    ).group_by(Chapter.id
    ).order_by(db.func.count(Quiz.id).desc()
    ).limit(5).all()
    
    active_chapters = [{
        'name': chapter.name,
        'subject_name': chapter.subject_name,
        'quiz_count': chapter.quiz_count
    } for chapter in active_chapters_query]
    
    # Question count distribution
    subquery = db.session.query(
        Quiz.id,
        db.func.count(Question.id).label('questions_per_quiz')
    ).join(Question
    ).group_by(Quiz.id
    ).subquery()

    quiz_question_distribution = db.session.query(
        subquery.c.questions_per_quiz.label('question_count'),
        db.func.count(subquery.c.id).label('quiz_count')
    ).group_by(subquery.c.questions_per_quiz
    ).order_by(subquery.c.questions_per_quiz
    ).limit(10).all()

    quiz_question_data = [{
        'question_count': item.question_count,
        'quiz_count': item.quiz_count
    } for item in quiz_question_distribution]
    
    return render_template(
        'admin/summary.html',
        active_page='summary',
        total_subjects=total_subjects,
        total_chapters=total_chapters,
        total_quizzes=total_quizzes,
        total_users=total_users,
        total_questions=total_questions,
        subject_data=subject_data,
        quiz_monthly_data=quiz_monthly_data,
        chapters_by_subject=chapters_by_subject,
        active_chapters=active_chapters,
        quiz_question_data=quiz_question_data
    )

@app.route('/user/quiz')
@login_required
def user_quiz():
    # Get all subjects with their chapters
    subjects = Subject.query.all()
    
    # Get all quizzes with additional information
    quizzes = db.session.query(
        Quiz,
        Subject.name.label('subject_name'),
        Chapter.name.label('chapter_name')
    ).join(
        Subject, Subject.id == Quiz.subject_id
    ).join(
        Chapter, Chapter.id == Quiz.chapter_id
    ).all()
    
    # Process quizzes data
    formatted_quizzes = []
    for quiz_data in quizzes:
        quiz = quiz_data[0]  # Get the Quiz object
        quiz_dict = quiz.to_dict()
        quiz_dict['subject'] = {'name': quiz_data.subject_name}
        quiz_dict['chapter'] = {'name': quiz_data.chapter_name}
        formatted_quizzes.append(quiz_dict)
    
    return render_template('user/user_quiz.html', subjects=subjects, quizzes=formatted_quizzes,active_page="user_quiz")


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            user = get_current_user()
            
            # Update only allowed fields
            user.full_name = request.form.get('full_name')
            user.qualification = request.form.get('qualification')
            user.dob = datetime.strptime(request.form.get('dob'), '%Y-%m-%d').date()
            
            # Handle password change if provided
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            
            if current_password and new_password:
                if check_password_hash(user.password, current_password):
                    user.password = generate_password_hash(new_password)
                else:
                    flash('Current password is incorrect', 'error')
                    return redirect(url_for('profile'))
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
            return redirect(url_for('profile'))
            
    return render_template('user/user_profile.html')

from datetime import datetime, timedelta
from sqlalchemy import func, and_

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Float, nullable=True)
    
    # Add relationship to store question-wise timing
    question_attempts = db.relationship('QuestionAttempt', backref='quiz_attempt', lazy=True)

class QuestionAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    selected_option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=True)
    is_correct = db.Column(db.Boolean, nullable=True)

@app.route('/user/summary')
@login_required
def user_summary():
    return render_template('user/user_summary.html', active_page='user_summary')

@app.route('/api/user/statistics')
@login_required
def get_user_statistics():
    user = get_current_user()
    current_date = datetime.utcnow()
    thirty_days_ago = current_date - timedelta(days=30)
    
    # Get basic statistics
    quiz_attempts = QuizAttempt.query.filter_by(user_id=user.id).all()
    total_quizzes = len(quiz_attempts)
    
    # Calculate average score
    average_score = db.session.query(func.avg(QuizAttempt.score))\
        .filter_by(user_id=user.id)\
        .scalar() or 0
        
    # Calculate total time spent
    total_time = sum(
        (attempt.end_time - attempt.start_time).total_seconds() / 3600 
        for attempt in quiz_attempts 
        if attempt.end_time
    )
    
    # Get subject-wise performance
    subject_performance = db.session.query(
        Subject.name.label('subject'),
        func.avg(QuizAttempt.score).label('averageScore')
    ).join(Quiz)\
        .join(QuizAttempt)\
        .filter(QuizAttempt.user_id == user.id)\
        .group_by(Subject.name)\
        .all()

    # Get daily activity for last 30 days
    daily_activity = []
    for i in range(30):
        date = current_date - timedelta(days=i)
        time_spent = db.session.query(
            func.sum(
                func.extract('epoch', QuizAttempt.end_time) - 
                func.extract('epoch', QuizAttempt.start_time)
            )/60
        ).filter(
            QuizAttempt.user_id == user.id,
            func.date(QuizAttempt.start_time) == date.date()
        ).scalar() or 0
        
        daily_activity.append({
            'date': date.strftime('%Y-%m-%d'),
            'timeSpent': round(time_spent, 2)
        })

    # Get recent quizzes
    recent_quizzes = db.session.query(
        QuizAttempt.start_time.label('date'),
        Subject.name.label('subject'),
        Chapter.name.label('chapter'),
        QuizAttempt.score,
        func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time)/60.0.label('timeTaken'),
        func.count(Question.id).label('totalQuestions')
    ).join(Quiz)\
        .join(Subject)\
        .join(Chapter)\
        .join(Question)\
        .filter(
            QuizAttempt.user_id == user.id,
            QuizAttempt.end_time.isnot(None)
        ).group_by(
            QuizAttempt.id,
            QuizAttempt.start_time,
            Subject.name,
            Chapter.name,
            QuizAttempt.score,
            QuizAttempt.end_time
        ).order_by(QuizAttempt.start_time.desc())\
        .limit(10)\
        .all()

    return jsonify({
        'totalQuizzes': total_quizzes,
        'averageScore': round(average_score, 1),
        'totalTimeHours': round(total_time, 1),
        'subjectsCovered': len(subject_performance),
        'subjectPerformance': [
            {'subject': item.subject, 'averageScore': round(item.averageScore, 1)}
            for item in subject_performance
        ],
        'dailyActivity': daily_activity,
        'recentQuizzes': [
            {
                'date': quiz.date.isoformat(),
                'subject': quiz.subject,
                'chapter': quiz.chapter,
                'score': round(quiz.score, 1),
                'timeTaken': round(quiz.timeTaken, 1),
                'totalQuestions': quiz.totalQuestions
            }
            for quiz in recent_quizzes
        ]
    })

@app.route('/api/quiz/<int:quiz_id>/time-analysis')
@login_required
def get_quiz_time_analysis(quiz_id):
    """Get time spent per question for a specific quiz attempt"""
    user = get_current_user()
    
    # Get the latest attempt for this quiz
    latest_attempt = QuizAttempt.query.filter_by(
        user_id=user.id,
        quiz_id=quiz_id
    ).order_by(QuizAttempt.start_time.desc()).first_or_404()
    
    # Get question-wise timing
    question_timing = db.session.query(
        Question.id,
        Question.text,
        func.extract('epoch', QuestionAttempt.end_time - QuestionAttempt.start_time).label('time_spent'),
        QuestionAttempt.is_correct
    ).join(QuestionAttempt)\
        .filter(QuestionAttempt.quiz_attempt_id == latest_attempt.id)\
        .all()
    
    return jsonify({
        'quizId': quiz_id,
        'attemptId': latest_attempt.id,
        'questionAnalysis': [
            {
                'questionId': q.id,
                'questionText': q.text,
                'timeSpentSeconds': round(q.time_spent, 1),
                'isCorrect': q.is_correct
            }
            for q in question_timing
        ]
    })

@app.route('/api/user/performance-comparison')
@login_required
def get_performance_comparison():
    """Compare user's performance with class average"""
    user = get_current_user()
    
    # Get user's average scores by subject
    user_scores = db.session.query(
        Subject.name.label('subject'),
        func.avg(QuizAttempt.score).label('user_avg')
    ).join(Quiz)\
        .join(QuizAttempt)\
        .filter(QuizAttempt.user_id == user.id)\
        .group_by(Subject.name)\
        .all()
    
    # Get class average scores by subject
    class_scores = db.session.query(
        Subject.name.label('subject'),
        func.avg(QuizAttempt.score).label('class_avg')
    ).join(Quiz)\
        .join(QuizAttempt)\
        .group_by(Subject.name)\
        .all()
    
    return jsonify({
        'comparison': [
            {
                'subject': user_score.subject,
                'userAverage': round(user_score.user_avg, 1),
                'classAverage': round(
                    next(
                        (s.class_avg for s in class_scores if s.subject == user_score.subject),
                        0
                    ),
                    1
                )
            }
            for user_score in user_scores
        ]
    })


@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    # Check if quiz exists and is available
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if user has already attempted this quiz
    existing_attempt = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_id=quiz_id
    ).first()
    
    if existing_attempt and existing_attempt.end_time:
        flash('You have already completed this quiz.', 'info')
        return redirect(url_for('quiz_result', attempt_id=existing_attempt.id))
    
    # Create new quiz attempt
    attempt = QuizAttempt(
        user_id=current_user.id,
        quiz_id=quiz_id,
        start_time=datetime.utcnow()
    )
    db.session.add(attempt)
    db.session.commit()
    
    return render_template('quiz_page.html', quiz=quiz)

@app.route('/api/quiz/<int:quiz_id>')
@login_required
def get_quiz_data(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return jsonify({
        'id': quiz.id,
        'title': quiz.quiz_id,
        'duration': quiz.duration,
        'questions': [question.to_dict() for question in quiz.questions]
    })

@app.route('/api/submit-quiz', methods=['POST'])
@login_required
def submit_quiz():
    data = request.get_json()
    attempt = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        end_time=None
    ).first_or_404()
    
    # Record end time
    attempt.end_time = datetime.utcnow()
    
    # Calculate score
    total_questions = len(attempt.quiz.questions)
    correct_answers = 0
    
    for question_index, selected_option in data['answers'].items():
        question = attempt.quiz.questions[int(question_index)]
        is_correct = selected_option == question.correct_option_index
        
        # Record question attempt
        question_attempt = QuestionAttempt(
            quiz_attempt_id=attempt.id,
            question_id=question.id,
            selected_option_id=question.options[selected_option].id,
            is_correct=is_correct
        )
        db.session.add(question_attempt)
        
        if is_correct:
            correct_answers += 1
    
    # Calculate percentage score
    attempt.score = (correct_answers / total_questions) * 100
    db.session.commit()
    
    return jsonify({
        'attemptId': attempt.id,
        'score': attempt.score
    })

@app.route('/quiz-result/<int:attempt_id>')
@login_required
def quiz_result(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    
    # Ensure user can only view their own results
    if attempt.user_id != current_user.id:
        abort(403)
    
    return render_template('quiz_result.html', attempt=attempt)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_account()
    app.run(debug=True)