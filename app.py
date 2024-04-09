from flask import Flask, render_template
from admin_blueprint import admin_blueprint
from user_blueprint import user_blueprint
from models import db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Use PostgreSQL database URI
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:1234@localhost/quiz"
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.register_blueprint(admin_blueprint, url_prefix='/admin')
app.register_blueprint(user_blueprint, url_prefix='/user')

db.init_app(app)

@app.route('/')
def home():
    return render_template('index.html', title='Home')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5039)
