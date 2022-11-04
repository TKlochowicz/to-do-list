from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from wtforms import StringField, SubmitField, PasswordField, DateTimeField, RadioField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms.validators import DataRequired, URL, Email
import os
from functools import wraps
from datetime import datetime

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[Email(), DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")

class NewTask(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    deadline = DateTimeField("Deadline date", validators=[DataRequired()], default=datetime.today)
    description = StringField("Description", validators=[DataRequired()])
    submit = SubmitField("Add Task")
    


app =Flask(__name__)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True,  nullable=False)
    password = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    task = relationship('Task', back_populates='user')

class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    user_id= db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="task")
    name = db.Column(db.String(50), nullable=False)
    deadline = db.Column(db.DateTime)
    done = db.Column(db.Boolean)
    description = db.Column(db.String(500))



lm=LoginManager()
lm.init_app(app)

with app.app_context():
    db.create_all()

def logged_in_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            abort(404)
        return function(*args, **kwargs)
    return decorated_function


@lm.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/', methods=['GET','POST'])
def home():
    user_logged_in=current_user.is_authenticated
    form=LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        user = db.session.query(User).filter_by(email=user_email).first()
        if user == None:
            flash('Register yourself!')
        else:
            database_password=user.password
            if check_password_hash(database_password, user_password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Password incorrect! Try again please.')
                return redirect(url_for('home'))
    if user_logged_in:
        to_do_list = db.session.query(Task).filter_by(user_id=current_user.id).all()
    else:
        to_do_list = []
    return render_template("index.html", form=form, logged_in=user_logged_in, to_do_list=to_do_list)

@app.route('/register', methods=['GET','POST'])
def register():
    user_logged_in=current_user.is_authenticated
    form=RegisterForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user == None:
            plain_password=form.password.data
            encrypted_password=generate_password_hash(plain_password, method="pbkdf2:sha256", salt_length=8)
            new_user=User(email=form.email.data, password=encrypted_password, name=form.name.data)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flash('We already have a user registered under this email. Login instead!')
            return redirect(url_for('home'))
    return render_template("register.html", form=form, logged_in=user_logged_in)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/create_task', methods=['GET','POST'])
@logged_in_only
def create():
    user_logged_in=current_user.is_authenticated
    form=NewTask()
    if form.validate_on_submit():
        user = current_user
        name = form.name.data
        deadline = form.deadline.data
        done = False
        description = form.description.data
        new_task = Task(user=user, name=name, deadline=deadline, done=done, description=description)
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template("create-task.html", form=form, logged_in=user_logged_in)


if __name__ =='__main__':
    app.run(debug=True)

