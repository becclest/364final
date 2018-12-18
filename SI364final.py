import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_bootstrap import Bootstrap
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, TextAreaField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand
from threading import Thread
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from yelp_api_key import api_key

############################
# Application configurations
############################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/finalbecclest"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug = True
bootstrap = Bootstrap(app)

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


def make_shell_context():
    return dict(app=app, db=db)


manager.add_command("shell", Shell(make_context=make_shell_context))
#########################
##### Set up Models #####
#########################
# Association Table between search terms (by cuisine and city) and restaurants -- Used from HW 4
tags = db.Table('tags', db.Column('search_id', db.Integer, db.ForeignKey(
    'searchterms.id')), db.Column('restaurant_id', db.Integer, db.ForeignKey('restaurants.id')))

# Association Table between restaurants and collections prepared by user -- Used from HW 4
user_collection = db.Table('user_collection', db.Column('user_id', db.Integer, db.ForeignKey(
    'restaurants.id')), db.Column('collection_id', db.Integer, db.ForeignKey('faveRestaurantCollection.id')))

# User-related Models


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    collection = db.relationship('FaveRestaurantCollection', backref='User')
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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Restaurant(db.Model):
    __tablename__ = "restaurants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    yelpid = db.Column(db.String(128), unique=True)
    URL = db.Column(db.String(256))
    rating = db.Column(db.Integer)
    reviews = db.relationship('ReviewItem', backref='Restaurant')

    def __repr__(self):
        return "{} (ID: {})".format(self.name, self.id)


class SearchCriteria(db.Model):
    __tablename__ = "searchterms"
    id = db.Column(db.Integer, primary_key=True)
    cuisine = db.Column(db.String(32))
    city = db.Column(db.String(32))
    restaurants = db.relationship('Restaurant', secondary=tags, backref=db.backref(
        'search', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return "{} in {}".format(self.cuisine, self.city)

# Model to store a personal collection of favorite restaurants


class FaveRestaurantCollection(db.Model):
    __tablename__ = "faveRestaurantCollection"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    restaurants = db.relationship('Restaurant', secondary=user_collection, backref=db.backref(
        'faveRestaurantCollection', lazy='dynamic'), lazy='dynamic')

# Model to store a personal collection of favorite restaurants


class ReviewItem(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurants.id"))
    review_text = db.Column(db.String(256))
    review_rating = db.Column(db.Integer)

    def __repr__(self):
        return "Rating {} | {}".format(self.review_rating, self.review_text)

#########################
######## Forms ##########
#########################


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


class RestaurantSearchForm(FlaskForm):
    cuisine = StringField('What kind of food are you in the mood for?',
                          validators=[Required()])
    city = StringField('What city do you want to search in?',
                       validators=[Required()])
    submit = SubmitField('Search')


class CollectionCreateForm(FlaskForm):
    name = StringField('Collection Name', validators=[Required()])
    restaurant_picks = SelectMultipleField('Restaurants to include:')
    submit = SubmitField("Create Collection")


class CreateReviewForm(FlaskForm):
    user_review = TextAreaField(
        "Write a review!", validators=[Required()])
    userRanking = IntegerField(
        "What is the new ranking of this restaurant?", validators=[Required()])
    submit = SubmitField('Update')


class UpdateReviewForm(FlaskForm):
    newRanking = StringField(
        "What is the new ranking of this restaurant?", validators=[Required()])
    submit = SubmitField('Update')


class UpdateButtonForm(FlaskForm):
    submit = SubmitField('Update')


class DeleteButtonForm(FlaskForm):
    submit = SubmitField('Delete')


###################################
##### Helper Functions ###########
###################################
def get_restaurant_from_yelp(cuisine, city):
    """ Returns data from Yelp API with up to 10 restaurants corresponding to the search input"""
    baseurl = "https://api.yelp.com/v3/businesses/search"
    params = {}
    params["term"] = cuisine
    params["limit"] = 10
    params["location"] = city

    headers = {
        'Authorization': 'Bearer %s' % api_key,
    }
    try:
        response = requests.get(baseurl, params=params, headers=headers)
        text = json.loads(response.text)
        todos = (text['businesses'])
        return todos

    except:
        return 'Trouble finding restaurant data'


def get_restaurant_by_id(id):
    rest = Restaurant.query.filter_by(id=id).first()
    return rest


def get_restaurant_review(id):
    baseurl = "https://api.yelp.com/v3/businesses/"
    response = get_restaurant_from_yelp()
    for g in response:

        baseurl = baseurl + id + '/reviews'
        headers = {
            'Authorization': 'Bearer %s' % api_key,
        }
        response = requests.get(baseurl, headers=headers)
        text = json.loads(response.text)
        todos = (text['reviews'])
    return todos


def get_or_create_restaurant(restaurant_name, yelpid, url, rating):
    rest = Restaurant.query.filter_by(name=restaurant_name).first()
    if not rest:
        print("Saving new restaurant")
        rest = Restaurant(name=restaurant_name,
                          yelpid=yelpid, URL=url, rating=rating)
        db.session.add(rest)
        db.session.commit()
    return rest


def get_or_create_search(cuisine, location):
    searchTerm = SearchCriteria.query.filter_by(
        cuisine=cuisine, city=location).first()
    print("Got existing search term, not adding more restaurants")
    if not searchTerm:
        searchTerm = SearchCriteria(cuisine=cuisine, city=location)
        rest_list = get_restaurant_from_yelp(cuisine, location)
        for x in rest_list:
            restaurant = get_or_create_restaurant(
                x['name'], x['id'], x['url'], x['rating'])
            searchTerm.restaurants.append(restaurant)
        db.session.add(searchTerm)
        db.session.commit()
        print("Added new search term to db")
    return searchTerm


def get_or_create_review(current_user, restaurant_id):
    reviewCollection = ReviewItem.query.filter_by(
        restaurant_id=restaurant_id, user_id=current_user.id).first()
    if not reviewCollection:
        reviewCollection = ReviewItem(
            restaurant_id=restaurant_id, user_id=current_user.id)
        db.session.add(reviewCollection)
        db.session.commit()
    return reviewCollection


def get_or_create_collection(name, current_user, rest_list=[]):
    restCollection = FaveRestaurantCollection.query.filter_by(
        name=name, user_id=current_user.id).first()
    if not restCollection:
        restCollection = FaveRestaurantCollection(
            name=name, user_id=current_user.id)
        for g in rest_list:
            restCollection.restaurants.append(g)
        db.session.add(restCollection)
        db.session.commit()
    return restCollection

###################################
##### Routes & view functions #####
###################################
# Error handling routes -- Provided


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Login routes -- Provided


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


@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."


# Main routes
@app.route('/', methods=['GET', 'POST'])
def index():
    form = RestaurantSearchForm()
    if form.validate_on_submit():
        cuisine = form.cuisine.data
        city = form.city.data
        get_or_create_search(cuisine, city)
        return redirect(url_for('search_results', cuisine=cuisine, city=city))
    return render_template('base.html', form=form)


@app.route('/search_results/<cuisine>/<city>')
def search_results(cuisine, city):
    term = SearchCriteria.query.filter_by(cuisine=cuisine, city=city).first()
    restaurants = term.restaurants.all()
    return render_template('search_results.html', restaurants=restaurants)

@app.route('/create_rest_collection', methods=["GET", "POST"])
@login_required
def create_collection():
    form = CollectionCreateForm()
    restaurants = Restaurant.query.all()
    choices = [(r.id, r.name) for r in restaurants]
    form.restaurant_picks.choices = choices
    if request.method == 'POST':
        selected_restaurants = form.restaurant_picks.data
        rest_objects = [get_restaurant_by_id(int(id)) for id in selected_restaurants]
        get_or_create_collection(current_user=current_user, name=form.name.data, rest_list=rest_objects)
        return redirect(url_for('collections'))
    return render_template('create_collection.html', form=form)

@app.route('/collections', methods=["GET", "POST"])
@login_required
def collections():
    # TODO 364: This view function should render the collections.html template so that only the current user's personal gif collection links will render in that template. Make sure to examine the template so that you send it the correct data!
    collection = FaveRestaurantCollection.query.filter_by(
        user_id=current_user.id).all()
    return render_template('collections.html', collections=collection)

@app.route('/collection/<id_num>')
def single_collection(id_num):
    id_num = int(id_num)
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    restaurants = collection.restaurants.all()
    return render_template('collection.html', collection=collection, restaurants=restaurants)

# Route to delete a whole Collection
@app.route('/collection/delete/<id_num>', methods=["GET", "POST"])
def delete(id_num):
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    db.session.delete(collection)
    db.session.commit()
    flash("Successfully deleted {}".format(collection.title))
    return redirect(url_for('collections'))


@app.route('/all_restaurants')
def all_restaurants():
    restaurants = Restaurant.query.all()
    return render_template('all_restaurants.html', all_rests=restaurants)


if __name__ == "__main__":
    db.create_all()
    manager.run()
    app.run(use_reloader=True)
