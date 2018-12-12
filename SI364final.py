import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand
from threading import Thread
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user

############################
# Application configurations
############################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/finalbecclest"
# Provided:
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

############################
# Login configurations setup
############################
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

##################
### App setup ####
##################
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Set up Shell context so it's easy to use the shell to debug
# Define function


def make_shell_context():
    return dict(app=app, db=db)


# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))


#########################
##### Set up Models #####
#########################

# Association table
cuisine_restaurant = db.Table('cuisine_restaurant', db.Column('restuarant_id', db.Integer, db.ForeignKey(
    'restaurants.id')), db.Column('cuisine_id', db.Integer, db.ForeignKey('cuisines.id')))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    collection = db.relationship('PersonalCollection', backref='User')
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True


class Restaurant(db.Model):
    __tablename__ = "restaurants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    city_id = db.Column(db.Integer, db.ForeignKey("cities.id"))
    cuisines = db.relationship('Cuisine', secondary=cuisine_restaurant, backref=db.backref(
        'restaurants', lazy='dynamic'), lazy='dynamic')


class City(db.Model):
    __tablename__ = "cities"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


class Cuisine(db.Model):
    __tablename__ = "cuisines"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


########################
##### Set up Forms #####
########################
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[
                        Required(), Length(1, 64), Email()])
    username = StringField('Username:', validators=[Required(), Length(1, 64), Regexp(
        '^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:', validators=[Required(), EqualTo(
        'password2', message="Passwords must match")])
    password2 = PasswordField("Confirm Password:", validators=[Required()])
    submit = SubmitField('Register User')

    # Additional checking methods for the form
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


###################################
##### Routes & view functions #####
###################################


# Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Login routes


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    db.create_all()
    manager.run()
    app.run(debug=True)
