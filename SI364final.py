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
from yelp_api_key import api_key

############################
# Application configurations
############################
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/finalbecclest"
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


def make_shell_context():
    return dict(app=app, db=db)


manager.add_command("shell", Shell(make_context=make_shell_context))
#########################
##### Set up Models #####
#########################
# Association Table between search terms (by cuisine and city) and restaurants



# Association Table between restaurants and collections prepared by user
user_collection = db.Table('user_collection', db.Column('user_id', db.Integer, db.ForeignKey(
    'restaurants.id')), db.Column('collection_id', db.Integer, db.ForeignKey('personalrestaurantsearchcollections.id')))


# Association table between review items and collections
review_list = db.Table('review_list', db.Column('item_id', db.Integer, db.ForeignKey(
    'items.id')), db.Column('list_id', db.Integer, db.ForeignKey('lists.id')))



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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Restaurant(db.Model):
    __tablename__ = "restaurants"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    yelpid = db.Column(db.String(128), unique=True)
    description = db.Column(db.String(225))
    def __repr__(self):
        return "{} (ID: {})".format(self.name, self.id)


 class SearchCriteria(db.Model):
    __tablename__ = "searchterms"
    id = db.Column(db.Integer, primary_key=True)
    cusine = db.Column(db.String(32)) 
    city = db.Column(db.String(32)) 
    restaurants = db.relationship('Restaurant', secondary=tags, backref=db.backref(
        'search', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return "{} in {}".format(self.cusine, self.city)

# Model to store a personal collection of favorite restaurants
class FaveRestaurantCollection(db.Model):
    __tablename__ = "faveRestaurantCollection"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    restaurants = db.relationship('Gif', secondary=user_collection, backref=db.backref(
        'faveRestaurantCollection', lazy='dynamic'), lazy='dynamic')
    reviews = db.relationship('ReviewItem', secondary=on_list, backref=db.backref(
        'lists', lazy='dynamic'), lazy='dynamic')


class ReviewItem(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurants.id"))
    rating = db.Column(db.Integer)
    review_text = db.Column(db.String(256))
    priority = db.Column(db.Integer)

    def __repr__(self):
        return "Rating {} | {}".format(self.rating, self.review)

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


class RestaurantForm(FlaskForm):
    cuisine = StringField('What kind of food are you in the mood for?',
                          validators=[Required()]))
    city=StringField('What city do you want to search in?',validators = [Required()]))
    submit=SubmitField('Search')


class CollectionCreateForm(FlaskForm):
    name=StringField('Collection Name', validators=[Required()])
    restaurant_picks=SelectMultipleField('Restaurants to include:')
    submit=SubmitField("Create Collection")

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
    """ Returns data from Yelp API with up to 10 gifs corresponding to the search input"""
    baseurl = "https://api.yelp.com/v3/businesses/search"
    params = {}
    params["term"] = cuisine
    params["limit"] = 10
    params["location"] = city

    headers = {
        'Authorization': 'Bearer %s' % api_key,
    }

    response = requests.get(baseurl, params=params, headers=headers)
    text = json.loads(response.text)
    todos = (text['businesses'])
    return todos

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

def get_restaurant_by_id(id):
    rest=Restaurant.query.filter_by(id=id).first()
    return rest

def get_or_create_restaurant(db_session, restaurant_name, city_name, cuisines_list=[]):
    city=get_or_create_city(db_session, city=city_name)
    restaurant=db_session.query(Restaurant).filter_by(
        name=restaurant_name, city_id=city.id).first()
    if restaurant:
        return restaurant
    else:
        restaurant=Restaurant(name=restaurant_name, city_id=city.id)
        for cuisine in cuisines_list:
            cuisine=get_or_create_cuisine(db_session, cuisine=cuisine)
            restaurant.cuisines.append(cuisine)
        db_session.add(restaurant)
        db_session.commit()
        return restaurant

def get_or_create_collection(name, current_user, rest_list=[]):
    restCollection=FaveRestaurantCollection.query.filter_by(
        name=name, user_id=current_user.id).first()
    if not restCollection:
        restCollection=FaveRestaurantCollection(
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
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
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
    form=RegistrationForm()
    if form.validate_on_submit():
        user=User(email=form.email.data,
                    username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# Main routes
@app.route('/', methods=['GET', 'POST'])
def index():
    form = RestaurantForm()
    if form.validate_on_submit():
        cuisine = form.cuisine.data
        city = form.city.data
        session['cuisine'] = cuisine
        session['city'] = city
        restaurant_data = get_restaurants(cuisine=cuisine, city=city)
        return render_template('addrestaurants.html', data=restaurant_data)
    return render_template('welcomepage.html', form=form)

@app.route('/all_restaurants')
def all_restaurants():
    restaurants = Restaurant.query.all()
    return render_template('all_rests.html', all_rests=restaurants)


@app.route('/create_rest_collection', methods=["GET", "POST"])
@login_required
def create_collection():
    form = CollectionCreateForm()
    gifs = Restaurant.query.all()
    choices = [(r.id, r.title) for r in restaurants]
    form.restaurant_picks.choices = choices

@app.route('/collections', methods=["GET", "POST"])
@login_required
def collections():
    colls=FaveRestaurantCollection.query.filter_by(user_id=current_user.id)
    return render_template('collections.html', collections=colls)


# Provided from HW 4
@app.route('/collection/<id_num>')
def single_collection(id_num):
    id_num = int(id_num)
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    rests = collection.restaurants.all()
    return render_template('collection.html', collection=collection, gifs=gifs)

# Route to update an individual ToDo item's priority
@app.route('/update/<item>', methods=["GET", "POST"])
def update(item):
    # Replace with code
    # This code should use the form you created above for updating the specific item and manage the process of updating the item's priority.
    # Once it is updated, it should redirect to the page showing all the links to todo lists.
    # It should flash a message: Updated priority of <the description of that item>
    # HINT: What previous class example is extremely similar?
    form = UpdateInfoForm()
    if form.validate_on_submit():
        new_priority = form.newPriority.data
        item_select = TodoItem.query.filter_by(id=item).first()
        item_select.priority = new_priority
        db.session.commit()
        flash("Updated priority of item: {}".format(item_select.description))
        return redirect(url_for('all_lists'))
    return render_template('update_item.html', item_id=item, form=form)


# Route to delete a whole Collection
@app.route('/delete/<lst>', methods=["GET", "POST"])
def delete(lst):
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    db.session.delete(collection)
    db.session.commit()
    flash("Successfully deleted {}".format(collection.title))
    return redirect(url_for('all_lists'))

if __name__ == "__main__":
    db.create_all()
    manager.run()
    app.run(use_reloader=True, debug=True)
