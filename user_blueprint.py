from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from models import db, Category, Level, User ,Question ,Option
from flask_bcrypt import Bcrypt
from sqlalchemy import func
import jwt
import datetime

user_blueprint = Blueprint('user', __name__)  
bcrypt = Bcrypt() 


def generate_token(user_id):
    token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 'your_secret_key')
    return token

# Login route
@user_blueprint.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return jsonify({'message': 'Username and password are required.'}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid username or password.'}), 401

        token = generate_token(user.id)
        # Render a template with success message
        return render_template('login_success.html', token=token)

    return render_template('login.html')




@user_blueprint.route('/userregister', methods=['POST'])
def register():
    data = request.form  # Use request.form to access form-encoded data
    if not data or 'username' not in data or 'password' not in data or 'email' not in data:
        return jsonify({'message': 'Username, password, and email are required.'}), 400
    
    username = data['username']
    password = data['password']
    email = data['email']

    if any(char.isdigit() for char in username):
        return jsonify({'message': 'Username cannot contain integers.'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists.'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists.'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
     

    return render_template('login.html', message='User created successfully'), 201


@user_blueprint.route('/logout', methods=['GET'])
def logout():
    return redirect(url_for('user.login'))  



@user_blueprint.route('/choose_category', methods=['GET'])
def choose_category():
    categories = Category.query.all()
    return render_template('select_category.html', categories=categories)

def get_levels_for_category(category_id):
    # Retrieve levels for the specified category_id
    levels = Level.query.filter_by(category_id=category_id).all()
    return levels

@user_blueprint.route('/start_quiz/<int:category_id>', methods=['GET'])
def start_quiz(category_id):
    
    levels = get_levels_for_category(category_id)
    return render_template('choose_level.html', levels=levels, category_id=category_id)
def get_questions_for_category_and_level(category_id, level_number):
    # Retrieve questions based on the selected category and level_number
    questions = Question.query \
        .join(Level, Question.level_id == Level.id) \
        .filter(Level.category_id == category_id, Level.level_number == level_number) \
        .all()

    return questions
import random


@user_blueprint.route('/display_questions', methods=['GET'])
def display_questions():
    category_id = request.args.get('category_id')
    level_number = request.args.get('level_number')
    page = request.args.get('page', default=1, type=int)  
    questions_per_page = 2  

    questions = get_questions_for_category_and_level(category_id, level_number, page, questions_per_page)

    if not questions.items:
        return "No questions found for the provided category and level."
    
    # Populate options for each question
    for question in questions.items:
        question.options = Option.query.filter_by(question_id=question.id).all()

    current_page = page
    total_pages = questions.pages
    return render_template('display_questions.html', 
                           questions=questions.items, 
                           current_page=current_page, 
                           total_pages=total_pages,
                           category_id=category_id,  
                           level_number=level_number)  


def get_questions_for_category_and_level(category_id, level_number, page=1, per_page=5):
    questions = Question.query \
        .join(Level, Question.level_id == Level.id) \
        .filter(Level.category_id == category_id, Level.level_number == level_number) \
        .paginate(page=page, per_page=per_page, error_out=False)
    return questions

@user_blueprint.route('/submit_answers', methods=['POST'])
def submit_answers():
    submitted_answers = request.form.getlist('answer')
    questions = Question.query.all()
    user_submissions = []
    correct_answers = []

    # Loop through submitted answers and retrieve corresponding questions and options
    for i, submitted_answer in enumerate(submitted_answers):
        question = questions[i]
        correct_answer = question.correct_answer
        options = Option.query.filter_by(question_id=question.id).all()
        correct_option_text = None
        
        # Find the correct option text
        for option in options:
            if option.option_text == correct_answer:
                correct_option_text = option.option_text
                break
        
        user_submissions.append({
            'question_text': question.question_text,
            'user_answer': submitted_answer,
            'correct_answer': correct_option_text
        })
        correct_answers.append(correct_option_text)

    # Redirect to the quiz result page with user submissions and correct answers
    return render_template('quiz_result.html', user_submissions=user_submissions, correct_answers=correct_answers)