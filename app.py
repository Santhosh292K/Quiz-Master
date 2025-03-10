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
class User(db.Model):
    __table_args__ = {'extend_existing': True}
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Add cascade delete
    quiz_attempts = db.relationship(
        'QuizAttempt', back_populates='user', lazy=True, 
        cascade="all, delete-orphan"
    )

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
    attempts = db.relationship('QuizAttempt', backref='quiz', lazy=True, 
                              cascade="all, delete-orphan")
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
class QuestionAttempt(db.Model):
    __tablename__ = 'question_attempt'
    
    id = db.Column(db.Integer, primary_key=True)
    quiz_attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    selected_option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=True)
    is_correct = db.Column(db.Boolean, nullable=True)

    def __repr__(self):
        return f'<QuestionAttempt {self.id} for Question {self.question_id}>'
class QuizAttempt(db.Model):
    __tablename__ = 'quiz_attempt'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    score = db.Column(db.Float, nullable=True)
    
    # Relationships
    user = db.relationship('User', back_populates='quiz_attempts')
    question_attempts = db.relationship('QuestionAttempt', backref='quiz_attempt', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<QuizAttempt {self.id} by User {self.user_id} for Quiz {self.quiz_id}>'

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
# Add these routes to your Flask application

from flask import jsonify

@app.route('/api/subject/<int:subject_id>/quizzes')
def get_subject_quizzes(subject_id):
    """API endpoint to get all quizzes for a specific subject"""
    quizzes = Quiz.query.filter_by(subject_id=subject_id).all()
    return jsonify({
        'quizzes': [
            {
                'id': quiz.id,
                'quiz_id': quiz.quiz_id,
                'date': quiz.date.isoformat(),
                'duration': quiz.duration,
                'chapter_id': quiz.chapter_id
            } for quiz in quizzes
        ]
    })

@app.route('/api/chapter/<int:chapter_id>/quizzes')
def get_chapter_quizzes(chapter_id):
    """API endpoint to get all quizzes for a specific chapter"""
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return jsonify({
        'quizzes': [
            {
                'id': quiz.id,
                'quiz_id': quiz.quiz_id,
                'date': quiz.date.isoformat(),
                'duration': quiz.duration,
                'subject_id': quiz.subject_id
            } for quiz in quizzes
        ]
    })

@app.route('/admin/quiz/<int:quiz_id>/view')
def view_quiz(quiz_id):
    """Route to view a specific quiz"""
    quiz = Quiz.query.get_or_404(quiz_id)
    # You can implement this page based on your quiz viewing requirements
    return render_template('admin/admin_quiz.html', quiz=quiz)
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
    
    # Quiz attempt statistics
    total_attempts = QuizAttempt.query.count()
    
    # Calculate average score
    avg_score_result = db.session.query(db.func.avg(QuizAttempt.score)).scalar()
    average_score = avg_score_result if avg_score_result is not None else 0
    
    # Calculate average time taken (in minutes)
    time_diff_expr = db.func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time) / 60
    avg_time_result = db.session.query(
        db.func.avg(time_diff_expr)
    ).filter(QuizAttempt.end_time != None).scalar()
    average_time = avg_time_result if avg_time_result is not None else 0
    
    # Calculate completion rate
    completed_attempts = QuizAttempt.query.filter(QuizAttempt.end_time != None).count()
    completion_rate = (completed_attempts / total_attempts * 100) if total_attempts > 0 else 0
    
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
    
    # Quiz attempt analysis
    quiz_attempts_query = db.session.query(
        Quiz.id,
        Quiz.quiz_id,
        Subject.name.label('subject_name'),
        Chapter.name.label('chapter_name'),
        db.func.count(QuizAttempt.id).label('attempts'),
        db.func.max(QuizAttempt.score).label('highest_score'),
        db.func.avg(QuizAttempt.score).label('average_score'),
        db.func.min(QuizAttempt.score).label('lowest_score'),
        db.func.avg(db.func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time) / 60).label('average_time')
    ).join(QuizAttempt, QuizAttempt.quiz_id == Quiz.id
    ).join(Subject, Subject.id == Quiz.subject_id
    ).join(Chapter, Chapter.id == Quiz.chapter_id
    ).filter(QuizAttempt.end_time != None
    ).group_by(Quiz.id, Subject.name, Chapter.name
    ).order_by(db.func.count(QuizAttempt.id).desc()
    ).all()
    
    quiz_attempts_data = [{
        'quiz_id': quiz.quiz_id,
        'subject_name': quiz.subject_name,
        'chapter_name': quiz.chapter_name,
        'attempts': quiz.attempts,
        'highest_score': quiz.highest_score,
        'average_score': quiz.average_score,
        'lowest_score': quiz.lowest_score,
        'average_time': quiz.average_time
    } for quiz in quiz_attempts_query]
    
    # Score distribution
    score_ranges = [
        {'min_score': 0, 'max_score': 20},
        {'min_score': 21, 'max_score': 40},
        {'min_score': 41, 'max_score': 60},
        {'min_score': 61, 'max_score': 80},
        {'min_score': 81, 'max_score': 100}
    ]
    
    score_distribution = []
    for score_range in score_ranges:
        count = QuizAttempt.query.filter(
            QuizAttempt.score >= score_range['min_score'],
            QuizAttempt.score <= score_range['max_score']
        ).count()
        if count > 0:
            score_distribution.append({
                'min_score': score_range['min_score'],
                'max_score': score_range['max_score'],
                'count': count
            })
    
    # Time taken distribution
    time_ranges = [
        {'min_time': 0, 'max_time': 5},
        {'min_time': 6, 'max_time': 10},
        {'min_time': 11, 'max_time': 15},
        {'min_time': 16, 'max_time': 20},
        {'min_time': 21, 'max_time': 30},
        {'min_time': 31, 'max_time': 60}
    ]
    
    time_distribution = []
    for time_range in time_ranges:
        min_seconds = time_range['min_time'] * 60
        max_seconds = time_range['max_time'] * 60
        
        count = db.session.query(QuizAttempt).filter(
            db.func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time) >= min_seconds,
            db.func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time) <= max_seconds,
            QuizAttempt.end_time != None
        ).count()
        
        if count > 0:
            time_distribution.append({
                'min_time': time_range['min_time'],
                'max_time': time_range['max_time'],
                'count': count
            })
    
    return render_template(
        'admin/summary.html',
        active_page='summary',
        total_subjects=total_subjects,
        total_chapters=total_chapters,
        total_quizzes=total_quizzes,
        total_users=total_users,
        total_questions=total_questions,
        total_attempts=total_attempts,
        average_score=average_score,
        average_time=average_time,
        completion_rate=completion_rate,
        subject_data=subject_data,
        quiz_monthly_data=quiz_monthly_data,
        chapters_by_subject=chapters_by_subject,
        active_chapters=active_chapters,
        quiz_question_data=quiz_question_data,
        quiz_attempts_data=quiz_attempts_data,
        score_distribution=score_distribution,
        time_distribution=time_distribution
    )
@app.route('/api/quiz/<quiz_id>/attempts')
@admin_required
def get_quiz_user_attempts(quiz_id):
    # Find the quiz by quiz_id
    quiz = Quiz.query.filter_by(quiz_id=quiz_id).first_or_404()
    
    # Get all attempts for this quiz with user information
    user_attempts = db.session.query(
        User.full_name.label('user_name'),
        QuizAttempt.score,
        db.func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time).label('time_taken_seconds'),
        QuizAttempt.start_time
    ).join(
        User, User.id == QuizAttempt.user_id
    ).filter(
        QuizAttempt.quiz_id == quiz.id,
        QuizAttempt.end_time != None  # Only include completed attempts
    ).order_by(
        QuizAttempt.score.desc()
    ).all()
    
    # Convert to minutes and prepare response
    result = []
    for attempt in user_attempts:
        result.append({
            'user_name': attempt.user_name,
            'score': attempt.score,
            'time_taken': attempt.time_taken_seconds / 60,  # Convert seconds to minutes
            'start_time': attempt.start_time.isoformat() if attempt.start_time else None
        })
    
    return jsonify(result)
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
    
    # Calculate average score - Fix for null values
    average_score = db.session.query(func.avg(QuizAttempt.score))\
        .filter(QuizAttempt.user_id == user.id, QuizAttempt.score.isnot(None))\
        .scalar() or 0
        
    # Calculate total time spent - Add safety check for None values
    total_time = sum(
        (attempt.end_time - attempt.start_time).total_seconds()
        for attempt in quiz_attempts 
        if attempt.end_time and attempt.start_time
    )
    
    # Get subject-wise performance - Fix join conditions
    subject_performance = db.session.query(
        Subject.name.label('subject'),
        func.avg(QuizAttempt.score).label('averageScore')
    ).join(Quiz, Quiz.subject_id == Subject.id)\
        .join(QuizAttempt, QuizAttempt.quiz_id == Quiz.id)\
        .filter(QuizAttempt.user_id == user.id, QuizAttempt.score.isnot(None))\
        .group_by(Subject.name)\
        .all()

    # Get daily activity for last 30 days - Fix date handling
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
            QuizAttempt.end_time.isnot(None),
            QuizAttempt.start_time.isnot(None),
            func.date(QuizAttempt.start_time) == date.date()
        ).scalar() or 0
        
        daily_activity.append({
            'date': date.strftime('%Y-%m-%d'),
            'timeSpent': round(time_spent, 2)
        })
    
    # Add Chapter Time data - Fix join conditions and null handling
    chapter_time = db.session.query(
        Chapter.name.label('chapter'),
        (func.sum(
            func.extract('epoch', QuizAttempt.end_time) - 
            func.extract('epoch', QuizAttempt.start_time)
        )/60.0).label('timeSpent')
    ).join(Quiz, Quiz.chapter_id == Chapter.id)\
        .join(QuizAttempt, QuizAttempt.quiz_id == Quiz.id)\
        .filter(
            QuizAttempt.user_id == user.id,
            QuizAttempt.end_time.isnot(None),
            QuizAttempt.start_time.isnot(None)
        ).group_by(Chapter.name)\
        .all()
    
    # Add Score Trends data - Fix date handling for string dates
    score_trends = db.session.query(
        func.date(QuizAttempt.start_time).label('date'),
        func.avg(QuizAttempt.score).label('score')
    ).filter(
        QuizAttempt.user_id == user.id,
        QuizAttempt.end_time.isnot(None),
        QuizAttempt.start_time.isnot(None),
        QuizAttempt.score.isnot(None)
    ).group_by(func.date(QuizAttempt.start_time))\
        .order_by(func.date(QuizAttempt.start_time))\
        .limit(30)\
        .all()

    # Get recent quizzes
    recent_quizzes = db.session.query(
        QuizAttempt.start_time.label('date'),
        Subject.name.label('subject'),
        Chapter.name.label('chapter'),
        QuizAttempt.score,
        (func.extract('epoch', QuizAttempt.end_time - QuizAttempt.start_time)/60.0).label('timeTaken'),
        func.count(Question.id).label('totalQuestions')
    ).join(Quiz, QuizAttempt.quiz_id == Quiz.id)\
        .join(Subject, Quiz.subject_id == Subject.id)\
        .join(Chapter, Quiz.chapter_id == Chapter.id)\
        .join(Question, Question.quiz_id == Quiz.id)\
        .filter(
            QuizAttempt.user_id == user.id,
            QuizAttempt.end_time.isnot(None),
            QuizAttempt.start_time.isnot(None),
            QuizAttempt.score.isnot(None)
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

    # Handle empty result sets gracefully
    return jsonify({
        'totalQuizzes': total_quizzes,
        'averageScore': round(average_score, 1) if average_score is not None else 0,
        'totalTimeHours': round(total_time, 1) if total_time is not None else 0,
        'subjectsCovered': len(subject_performance),
        'subjectPerformance': [
            {'subject': item.subject, 'averageScore': round(item.averageScore, 1) if item.averageScore is not None else 0}
            for item in subject_performance
        ],
        'dailyActivity': daily_activity,
        'chapterTime': [
            {'chapter': item.chapter, 'timeSpent': round(item.timeSpent, 1) if item.timeSpent is not None else 0}
            for item in chapter_time
        ],
        'scoretrends': [
            # Fix: Don't call strftime on item.date as it's already a string
            {'date': str(item.date), 'score': round(item.score, 1) if item.score is not None else 0}
            for item in score_trends
        ],
        'recentQuizzes': [
            {
                'date': quiz.date.isoformat() if hasattr(quiz.date, 'isoformat') else str(quiz.date),
                'subject': quiz.subject,
                'chapter': quiz.chapter,
                'score': round(quiz.score, 1) if quiz.score is not None else 0,
                'timeTaken': round(quiz.timeTaken) if quiz.timeTaken is not None else 0,
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
                'timeSpentSeconds':q.time_spent,
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
from flask import jsonify, request, render_template, redirect, url_for, flash, abort
from datetime import datetime, timedelta
from sqlalchemy import and_
from functools import wraps

# Custom decorator for quiz attempt validation
def validate_quiz_attempt(f):
    @wraps(f)
    def decorated_function(quiz_id, *args, **kwargs):
        quiz = Quiz.query.get_or_404(quiz_id)
        attempt = QuizAttempt.query.filter(
            and_(
                QuizAttempt.user_id == get_current_user().id,
                QuizAttempt.quiz_id == quiz_id,
                QuizAttempt.end_time.is_(None)
            )
        ).first()
        
        if attempt:
            time_elapsed = datetime.utcnow() - attempt.start_time
            if time_elapsed > timedelta(minutes=quiz.duration):
                attempt.end_time = attempt.start_time + timedelta(minutes=quiz.duration)
                attempt.score = 0
                db.session.commit()
                flash('Quiz attempt expired', 'warning')
                return redirect(url_for('quiz_result', attempt_id=attempt.id))
        
        return f(quiz_id, quiz=quiz, attempt=attempt, *args, **kwargs)
    return decorated_function

# Quiz taking routes
@app.route('/quiz/<int:quiz_id>/start')
@login_required
def start_quiz(quiz_id):
    """Initialize a new quiz attempt or resume existing attempt"""
    quiz = Quiz.query.get_or_404(quiz_id)
    user = get_current_user()
    
    # Check for existing incomplete attempt
    existing_attempt = QuizAttempt.query.filter(
        and_(
            QuizAttempt.user_id == user.id,
            QuizAttempt.quiz_id == quiz_id,
            QuizAttempt.end_time.is_(None)
        )
    ).first()
    
    if existing_attempt:
        time_elapsed = datetime.utcnow() - existing_attempt.start_time
        if time_elapsed > timedelta(minutes=quiz.duration):
            existing_attempt.end_time = existing_attempt.start_time + timedelta(minutes=quiz.duration)
            existing_attempt.score = 0
            db.session.commit()
            flash('Previous attempt expired. Starting new attempt.', 'info')
        else:
            return redirect(url_for('take_quiz', quiz_id=quiz_id))
    
    # Check for completed attempts
    completed_attempt = QuizAttempt.query.filter(
        and_(
            QuizAttempt.user_id == user.id,
            QuizAttempt.quiz_id == quiz_id,
            QuizAttempt.end_time.isnot(None)
        )
    ).first()
    
    if completed_attempt:
        flash('You have already completed this quiz. Starting new attempt.', 'info')
    
    # Create new attempt
    new_attempt = QuizAttempt(
        user_id=user.id,
        quiz_id=quiz_id,
        start_time=datetime.utcnow()
    )
    db.session.add(new_attempt)
    db.session.commit()
    
    return redirect(url_for('take_quiz', quiz_id=quiz_id))

@app.route('/quiz/<int:quiz_id>')
@login_required
@validate_quiz_attempt
def take_quiz(quiz_id, quiz, attempt):
    """Display quiz interface"""
    if not attempt:
        return redirect(url_for('start_quiz', quiz_id=quiz_id))
    
    time_remaining = quiz.duration * 60 - (datetime.utcnow() - attempt.start_time).total_seconds()
    
    return render_template('user/quiz_page.html', 
                         quiz=quiz, 
                         attempt=attempt,
                         time_remaining=time_remaining)

@app.route('/api/quiz/<int:quiz_id>/state')
@login_required
@validate_quiz_attempt
def get_quiz_state(quiz_id, quiz, attempt):
    if not attempt:
        return jsonify({'error': 'No active quiz attempt'}), 404
    
    # Get answered questions with full details
    question_attempts = QuestionAttempt.query.filter_by(
        quiz_attempt_id=attempt.id
    ).all()
    
    answered_questions = {}
    for qa in question_attempts:
        answered_questions[qa.question_id] = {
            'selected_option_id': qa.selected_option_id,
            'is_correct': qa.is_correct,
            'time_spent': (qa.end_time - qa.start_time).total_seconds() if qa.end_time else None
        }
    
    time_remaining = quiz.duration * 60 - (datetime.utcnow() - attempt.start_time).total_seconds()
    
    return jsonify({
        'quiz_id': quiz.id,
        'attempt_id': attempt.id,
        'time_remaining': max(0, time_remaining),
        'answered_questions': answered_questions,
        'total_questions': len(quiz.questions),
        'is_complete': attempt.end_time is not None,
        'score': attempt.score if attempt.end_time else None
    })

@app.route('/api/quiz/<int:quiz_id>/question/<int:question_id>/answer', methods=['POST'])
@login_required
@validate_quiz_attempt
def answer_question(quiz_id, question_id, quiz, attempt):
    """Record an answer for a specific question"""
    if not attempt:
        return jsonify({'error': 'No active quiz attempt'}), 404
    
    data = request.get_json()
    if 'selected_option' not in data:
        return jsonify({'error': 'Selected option not provided'}), 400
    
    question = Question.query.get_or_404(question_id)
    if question.quiz_id != quiz_id:
        return jsonify({'error': 'Question does not belong to this quiz'}), 400
    
    selected_option = data['selected_option']
    if not (0 <= selected_option < len(question.options)):
        return jsonify({'error': 'Invalid option selected'}), 400
    
    # Record or update question attempt
    question_attempt = QuestionAttempt.query.filter_by(
        quiz_attempt_id=attempt.id,
        question_id=question_id
    ).first()
    
    if not question_attempt:
        question_attempt = QuestionAttempt(
            quiz_attempt_id=attempt.id,
            question_id=question_id,
            start_time=datetime.utcnow()
        )
        db.session.add(question_attempt)
    
    question_attempt.selected_option_id = question.options[selected_option].id
    question_attempt.end_time = datetime.utcnow()
    question_attempt.is_correct = (selected_option == question.correct_option_index)
    
    try:
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to save answer'}), 500
@app.route('/api/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
@validate_quiz_attempt
def submit_quiz(quiz_id, quiz, attempt):
    """Submit the quiz and calculate final score"""
    if not attempt:
        return jsonify({'error': 'No active quiz attempt'}), 404
    
    try:
        # First, let's check if this attempt is already completed
        if attempt.end_time is not None:
            return jsonify({'error': 'This quiz attempt has already been submitted'}), 400
        
        # Calculate score
        question_attempts = QuestionAttempt.query.filter_by(
            quiz_attempt_id=attempt.id
        ).all()
        
        total_questions = len(quiz.questions)
        if total_questions == 0:
            return jsonify({'error': 'Invalid quiz: no questions found'}), 400
            
        correct_answers = sum(1 for qa in question_attempts if qa.is_correct)
        
        # Record final score and end time
        attempt.score = (correct_answers / total_questions) * 100
        attempt.end_time = datetime.utcnow()
        
        # Commit this change first to ensure the current attempt is saved
        db.session.commit()
        
        # Now, in a separate transaction, handle previous attempts
        try:
            # Find previous completed attempts (excluding the one we just saved)
            previous_attempts = QuizAttempt.query.filter(
                QuizAttempt.user_id == attempt.user_id,
                QuizAttempt.quiz_id == quiz_id,
                QuizAttempt.id != attempt.id,
                QuizAttempt.end_time.isnot(None)
            ).all()
            
            if previous_attempts:
                for prev_attempt in previous_attempts:
                    # Instead of deleting, we could mark them as archived
                    # or just leave them if deletion is causing issues
                    db.session.delete(prev_attempt)
                db.session.commit()
        except Exception as inner_e:
            # If there's an error cleaning up old attempts, log it but don't fail the submission
            db.session.rollback()
            app.logger.error(f"Error cleaning up previous attempts: {str(inner_e)}")
            # Continue with the success response since the current attempt was saved
        
        return jsonify({
            'attempt_id': attempt.id,
            'score': attempt.score,
            'redirect_url': url_for('quiz_result', attempt_id=attempt.id)
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error submitting quiz: {str(e)}")
        # Include the traceback for more detailed error information
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to submit quiz. Please contact support.'}), 500
@app.route('/quiz/result/<int:attempt_id>')
@login_required
def quiz_result(attempt_id):
    """Display quiz results"""
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    
    # Ensure user can only view their own results
    if attempt.user_id != get_current_user().id:
        abort(403)
    
    # Get question-wise results
    question_results = []
    for question in attempt.quiz.questions:
        attempt_data = QuestionAttempt.query.filter_by(
            quiz_attempt_id=attempt.id,
            question_id=question.id
        ).first()
        
        if attempt_data:
            result = {
                'question': question.question_text,
                'selected_option': next(
                    (opt.option_text for opt in question.options 
                     if opt.id == attempt_data.selected_option_id),
                    None
                ),
                'correct_option': question.options[question.correct_option_index].option_text,
                'is_correct': attempt_data.is_correct,
                'explanation': question.explanation,
                'time_spent': (attempt_data.end_time - attempt_data.start_time).total_seconds() \
                    if attempt_data.end_time else None
            }
            question_results.append(result)
    
    return render_template(
        'user/quiz_result.html',
        attempt=attempt,
        quiz=attempt.quiz,  # Add this line
        question_results=question_results,
        total_time=(attempt.end_time - attempt.start_time).total_seconds()
    )

@app.route('/api/quiz/<int:quiz_id>/questions')
@login_required
@validate_quiz_attempt
def get_quiz_questions(quiz_id, quiz, attempt):
    """Get quiz questions for an active attempt"""
    if not attempt:
        return jsonify({'error': 'No active quiz attempt'}), 404
    
    questions = []
    for question in quiz.questions:
        questions.append({
            'id': question.id,
            'text': question.question_text,
            'options': [{'id': opt.id, 'text': opt.option_text} 
                       for opt in question.options]
        })
    
    return jsonify({
        'quiz_id': quiz.id,
        'title': quiz.quiz_id,
        'questions': questions,
        'duration': quiz.duration,
        'attempt_id': attempt.id
    })
# Additional route needed for clearing answers
@app.route('/api/quiz/<int:quiz_id>/question/<int:question_id>/answer', methods=['DELETE'])
@login_required
@validate_quiz_attempt
def clear_question_answer(quiz_id, question_id, quiz, attempt):
    """Clear an answer for a specific question"""
    if not attempt:
        return jsonify({'error': 'No active quiz attempt'}), 404
    
    # Find and delete the question attempt
    question_attempt = QuestionAttempt.query.filter_by(
        quiz_attempt_id=attempt.id,
        question_id=question_id
    ).first()
    
    if question_attempt:
        try:
            db.session.delete(question_attempt)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to clear answer: {str(e)}'}), 500
    
    return jsonify({'success': True})  # Nothing to clear



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_account()
    app.run(debug=True,host='0.0.0.0')