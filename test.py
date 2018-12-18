import requests
import json
from yelp_api_key import api_key
from pprint import pprint


def get_restaurant_from_yelp(cuisine, city):
    """ Returns data from Giphy API with up to 5 gifs corresponding to the search input"""
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


gogo = get_restaurant_from_yelp('mexican', 'NYC')
for g in gogo:
    print (g['name'], g['rating'])


@app.route('/create_rest_collection', methods=["GET", "POST"])
@login_required
def create_collection():
    form = CollectionCreateForm()
    restaurants = Restaurant.query.all()
    choices = [(r.id, r.title) for r in restaurants]
    form.restaurant_picks.choices = choices


@app.route('/collections', methods=["GET", "POST"])
@login_required
def collections():
    colls = FaveRestaurantCollection.query.filter_by(user_id=current_user.id)
    return render_template('collections.html', collections=colls)


# Provided from HW 4
@app.route('/collection/<id_num>')
def single_collection(id_num):
    id_num = int(id_num)
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    rests = collection.restaurants.all()
    return render_template('collection.html', collection=collection, rests=rests)

# Route to update an individual ToDo item's priority


@app.route('/update/<review>', methods=["GET", "POST"])
def update(review):
    form = UpdateReviewForm()
    if form.validate_on_submit():
        new_priority = form.newRanking.data
        review_select = ReviewItem.query.filter_by(id=review).first()
        review_select.rating = new_rating
        db.session.commit()
        flash("Updated review of restaurant: {}".format(
            item_select.restaurant_id))
        return redirect(url_for('collections'))
    return render_template('update_item.html', item_id=item, form=form)


@app.route("/create_review/<restaurant_id>/review", methods=["GET", "POST"])
@login_required
def create_review(restaurant_id):
    restaurant = Restaurant.query.get_or_404(restaurant_id)
    form = CreateReviewForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            review = ReviewItem(review_text=form.user_review.data,
                                restaurant_id=restaurant.id, review_rating=form.userRanking.data)
            db.session.add(review)
            db.session.commit()
            flash("Your review has been added to this restaurant", "success")
    return render_template("reviews.html", form=form)


# Route to delete a whole Collection
@app.route('/delete/<lst>', methods=["GET", "POST"])
def delete(lst):
    collection = FaveRestaurantCollection.query.filter_by(id=id_num).first()
    db.session.delete(collection)
    db.session.commit()
    flash("Successfully deleted {}".format(collection.title))
    return redirect(url_for('collections'))

@app.route('/all_restaurants')
def all_restaurants():
    restaurants = Restaurant.query.all()
    return render_template('all_rests.html', all_rests=restaurants)
