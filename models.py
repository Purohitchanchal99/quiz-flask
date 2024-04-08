from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(120), unique=True)  # Add this line to include the email column
    password = db.Column(db.String(80))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Level(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    level_number = db.Column(db.Integer, nullable=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level_id = db.Column(db.Integer, db.ForeignKey('level.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)

    level = db.relationship('Level', backref=db.backref('questions', lazy=True))
    level = db.relationship('Level', backref=db.backref('questions', lazy=True))

    def __repr__(self):
        return f"<Question {self.id}>"


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    @classmethod
    def check_username_exists(cls, username):
        return cls.query.filter_by(username=username).first() is not None

    @staticmethod
    def check_username_exists(username):
        return Admin.query.filter_by(username=username).first() is not None

    def __repr__(self):
        return f"<Admin {self.username}>"
class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    option_text = db.Column(db.String(255), nullable=False)

class UserSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    question_id = db.Column(db.Integer, nullable=False)
    selected_option_id = db.Column(db.Integer, nullable=False)