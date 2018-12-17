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
