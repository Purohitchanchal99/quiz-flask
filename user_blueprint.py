from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from models import db, Category, Level, User ,Question ,Option# Import required models
from flask_bcrypt import Bcrypt
from sqlalchemy import func, asc

import jwt
import datetime

user_blueprint = Blueprint('user', __name__)  # Define Blueprint
bcrypt = Bcrypt()  # Initialize Bcrypt for password hashing

# Function to generate JWT token
def generate_token(user_id):
    token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=220)}, 'your_secret_key')
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

    # Handle GET request (e.g., render login form)
    return render_template('login.html')

# Route to display available categories for quiz

# Route to register a new user
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
     
    # Return a success message
    return render_template('login.html', message='User created successfully'), 201

# Route to logout
@user_blueprint.route('/logout', methods=['GET'])
def logout():
    return redirect(url_for('user.login'))  

# Route to choose a category for quiz


def get_levels_for_category(category_id):
    # Retrieve levels for the specified category_id
    levels = Level.query.filter_by(category_id=category_id).all()
    return levels

@user_blueprint.route('/start_quiz/<int:category_id>', methods=['GET'])
def start_quiz(category_id):
    # Get levels for the selected category
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

from random import shuffle
@user_blueprint.route('/display_questions', methods=['GET'])
def display_questions():
    category_id = request.args.get('category_id')
    level_number = request.args.get('level_number')
    page = request.args.get('page', default=1, type=int)  # Get the page number from the request query parameters
    questions_per_page = 2  # Define the number of questions per page

    # Retrieve questions for the selected category and level
    questions = get_questions_for_category_and_level(category_id, level_number, page, questions_per_page)

    # If no questions found, return an error message
    if not questions.items:
        return "No questions found for the provided category and level."
# Retrieve options for each question
    for question in questions:
        question.options = get_options_for_question(question.id)

    # Pass the current page number and total pages to the template context
    current_page = page
    total_pages = questions.pages

    # Render the template to display questions
    return render_template('display_questions.html', 
                           questions=questions.items, 
                           current_page=current_page, 
                           total_pages=total_pages,
                           category_id=category_id,  # Pass category_id to the template
                           level_number=level_number)  # Pass level_number to the template


def get_questions_for_category_and_level(category_id, level_number, page=1, per_page=5):
    # Retrieve questions for the specified category_id and level_number
    questions = Question.query \
        .join(Level, Question.level_id == Level.id) \
        .filter(Level.category_id == category_id, Level.level_number == level_number) \
        .paginate(page=page, per_page=per_page, error_out=False)
    
    # Shuffle the order of questions
    questions.items = list(questions.items)
    shuffle(questions.items)
    
    return questions

def get_options_for_question(question_id, page=1, per_page=5):
    # Retrieve options for the specified question_id
    options = Option.query.filter_by(question_id=question_id).paginate(page=page, per_page=per_page)
    
    # Shuffle the order of options
    options.items = list(options.items)
    shuffle(options.items)
    
    return options



@user_blueprint.route('/submit_answers', methods=['POST'])
def submit_answers():
    category_id = request.form.get('category_id')
    level_number = request.form.get('level_number')

    # Retrieve all questions for the given category and level
    questions = Question.query \
        .join(Level, Question.level_id == Level.id) \
        .filter(Level.category_id == category_id, Level.level_number == level_number) \
        .all()

    user_submissions = []

    # Iterate over each question to gather user submissions and correct answers
    for question in questions:
        user_answer = request.form.get('answer_{}'.format(question.id))
        correct_answer = question.correct_answer
        user_submissions.append({
            'question_text': question.question_text,
            'user_answer': user_answer,
            'correct_answer': correct_answer
        })

    return render_template('quiz_result.html', user_submissions=user_submissions)