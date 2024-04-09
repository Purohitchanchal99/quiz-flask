from flask import Blueprint, request, jsonify, current_app, render_template, redirect, url_for, session,abort

from models import db, Admin, User, Category, Level, Question, Option
from sqlalchemy.exc import IntegrityError 

from flask_bcrypt import Bcrypt
import jwt

admin_blueprint = Blueprint('admin', __name__)
bcrypt = Bcrypt()

# Predefined value for admin registration code
admin_registration_code = 'admin123'

# Function to generate JWT token
def generate_token(username):
    token = jwt.encode({'username': username}, current_app.config['SECRET_KEY'], algorithm='HS256')
    return token

# API route for admin registration
@admin_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        registration_code = data.get('registration_code')

        if not username or not password or not registration_code:
            return jsonify({'message': 'Username, password, and registration code are required.'}), 400

        # Check if the registration code matches the predefined value
        if registration_code != admin_registration_code:
            return jsonify({'message': 'Invalid registration code.'}), 401

        # Check if username already exists
        if Admin.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists.'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = Admin(username=username, password=hashed_password)
        db.session.add(admin)
        db.session.commit()
        return redirect(url_for('admin.login'))

    return render_template('adminregistration.html')

# API route for admin login
@admin_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'message': 'Username and password are required.'}), 400
        admin = Admin.query.filter_by(username=username).first()
        if not admin or not bcrypt.check_password_hash(admin.password, password):
            return jsonify({'message': 'Invalid username or password.'}), 401
        token = generate_token(username)
        session['token'] = token
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('adminlogin.html')

# API route for admin logout
@admin_blueprint.route('/logout', methods=['GET'])
def logout():
    session.pop('token', None)
    return redirect(url_for('admin.login'))

# API route for admin dashboard
@admin_blueprint.route('/dashboard', methods=['GET'])
def admin_dashboard():
    token = session.get('token')
    if not token:
        return redirect(url_for('admin.login'))

    try:
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = decoded_token['username']

        # Check if the user is an admin
        admin = Admin.query.filter_by(username=username).first()
        if not admin:
            abort(403)  # Forbidden: User is not an admin

        # Get count of registered users
        user_count = User.query.count()

        # Get count of categories
        category_count = Category.query.count()

        # Pass token to the template
        return render_template('admin_dashboard.html', username=username, user_count=user_count, category_count=category_count, token=token)
    except jwt.ExpiredSignatureError:
        return redirect(url_for('admin.login'))  # Redirect to login if token is expired
    except (jwt.InvalidTokenError, KeyError):
        abort(401)  # Unauthorized: Invalid token or missing username in token


# Function to check if the user is an admin


# Route to add a new category
@admin_blueprint.route('/add_category', methods=['POST'])
def manage_categories():
    if request.method == 'POST':
        try:
            name = request.form.get('name')  # Get name from form data
            if not name:
                return jsonify({'error': 'Name is required'}), 400
            
            # Check if the category already exists
            existing_category = Category.query.filter_by(name=name).first()
            if existing_category:
                return jsonify({'error': 'Category already exists'}), 400
            
            # Add the category
            category = Category(name=name)
            db.session.add(category)
            db.session.commit()
            
            # Add three levels for the category (easy, medium, hard)
            levels = [('easy', 1), ('medium', 2), ('hard', 3)]
            for level_name, level_number in levels:
                level = Level(category_id=category.id, level_number=level_number)
                db.session.add(level)
            
            db.session.commit()
            # return render_template('add_question.html', category_id=category.id)
                
            return jsonify({'message': 'Category added successfully with easy, medium, and hard levels'}), 201
        except Exception as e:
            db.session.rollback()  # Rollback the transaction in case of an error
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 405

@admin_blueprint.route('/edit_category/<int:category_id>', methods=['PUT'])
def edit_category(category_id):
    if request.method == 'PUT':
        try:
            # Get JSON data from request
            data = request.json
            if not data:
                return jsonify({'error': 'No JSON data received'}), 400

            # Get category name from JSON data
            name = data.get('name')
            if not name:
                return jsonify({'error': 'Name is required in JSON data'}), 400
            
            # Check if the category exists
            category = Category.query.get(category_id)
            if not category:
                return jsonify({'error': 'Category not found'}), 404
            
            # Update the category name
            category.name = name
            db.session.commit()
            
            return jsonify({'message': 'Category updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 405

# Route to delete a category
@admin_blueprint.route('/delete_category/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    if request.method == 'DELETE':
        try:
            # Check if the category exists
            category = Category.query.get(category_id)
            if not category:
                return jsonify({'error': 'Category not found'}), 404
            
            # Delete the category
            db.session.delete(category)
            db.session.commit()
            
            return jsonify({'message': 'Category deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()  # Rollback the transaction in case of an error
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Invalid request method'}), 405


    
# API route to get all categories with their IDs
@admin_blueprint.route('/allcategories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    categories_data = [{'id': category.id, 'name': category.name} for category in categories]
    return jsonify(categories_data), 200

@admin_blueprint.route('/add_question_category_level', methods=['POST'])
def add_question_category_level():
    data = request.get_json()

    # Validate incoming data
    required_fields = ('category_id', 'level_number', 'question_text', 'options', 'correct_answer')
    if not all(key in data for key in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    category_id = data['category_id']
    level_number = data['level_number']
    question_text = data['question_text']
    options = data['options']
    correct_answer = data['correct_answer']

    # Retrieve or create the Category and Level objects
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': f'Category with ID {category_id} not found'}), 404

    level = Level.query.filter_by(category_id=category_id, level_number=level_number).first()
    if not level:
        level = Level(category_id=category_id, level_number=level_number)
        db.session.add(level)
        db.session.commit()

    # Create the Question object
    question = Question(level_id=level.id, question_text=question_text, correct_answer=correct_answer)
    db.session.add(question)
    db.session.commit()  # Commit to generate the question's ID

    # Create the Option objects
    for option_text in options:
        option = Option(question_id=question.id, option_text=option_text)  # Assign question_id here
        db.session.add(option)

    db.session.commit()

    return jsonify({'message': 'Question added successfully'}), 201

    
@admin_blueprint.route('/update_question/<int:question_id>', methods=['PUT'])
def update_question(question_id):
    if request.method == 'PUT':
        data = request.get_json()

        # Validate incoming data
        if not all(key in data for key in ('question_text', 'options', 'correct_answer')):
            return jsonify({'error': 'Missing required fields'}), 400
        
@admin_blueprint.route('/questions', methods=['GET'])
def get_question_ids_with_texts():
    try:
        # Query the database to retrieve question IDs and texts
        questions = Question.query.all()
        question_data = [{'id': question.id, 'text': question.question_text} for question in questions]
        
        # Return question IDs and texts as a JSON response
        return jsonify({'questions': question_data}), 200
    except Exception as e:
        # Handle any errors that occur during the process
        return jsonify({'error': str(e)}), 500
@admin_blueprint.route('/admin_code', methods=['GET'])
def get_admin_code():
    try:
        return jsonify({'admin_code': admin_registration_code}), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error occurred. Please try again later.'}), 500