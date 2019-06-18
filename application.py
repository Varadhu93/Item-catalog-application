#!/usr/bin/env python3
'''
application.py - Implementation of the item catalog project
'''
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash,
                   get_flashed_messages)
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Catalog, Item
from flask import session as login_session

import logging
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

"""
Connecting to Item catalog database
"""
engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler('itemcatalog.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('''%(asctime)s - %(name)s - 
                              %(levelname)s - %(message)s''')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

"""
Client Id Authentication
Reading the JSON values from client_secrets.json
"""
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    Logic to FB Authentication
    Reading JSON values from fb_client_secrets.json
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    logger.info("Inside fbconnect(), Open and read fb_client_secrets.json")
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = '''https://graph.facebook.com/oauth/access_token?grant_type=
    fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s''' % (
        app_id, app_secret, access_token)

    h = httplib2.Http()
    result = h.request(url.encode(), 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = '''https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,
    email''' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    logger.info("Setting json values to login_session")
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = '''https://graph.facebook.com/v2.8/me/picture?access_token=%s&
    redirect=0&height=200&width=200''' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    logger.info("After FB authenticating, Check if user already exists in DB")
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = "<h6><strong>Redirecting...</strong></h6>"
    flash("Welcome {} you are now logged in".format(login_session['username']))
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """
    Logic to disconnect FB session
    """
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    logger.info("fbdisconnect(), Logged out")
    return "you have been logged out"


@app.route('/login')
def showLogin():
    """
    Logic to re-direct to Login page
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    # Add to client session the state string in order to preven anti-forgery
    login_session['state'] = state
    logger.info("Display login page")
    return render_template('login.html', currentPage='login', STATE=state)


@app.route('/disconnect')
def disconnect():
    """
    Logic to disconnect and clear
    a User's session
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        login_session.clear()
        logger.info("Inside disconnect(), Clear user session and logging out")
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalogApp'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalogApp'))


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Google Authentication
    Reads data from client_secrets.json
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        logger.info("Inside gconnect(), Open and read client_secrets.json")
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1].decode())
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('''Current user is already connected.
                                            '''), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    if 'name' in data:
        login_session['username'] = data['name']
    else:
        login_session['username'] = 'Admin_User'
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = "<h6><strong>Redirecting...</strong></h6>"
    flash("Welcome {} you are now logged in".format(login_session['username']))
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    Disconnect User's Google session
    """
    # Only disconnect a connected user.
    logger.info("Inside gdisconnect(), Disconnect google connect session")
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createUser(login_session):
    """
    Adding a new User into User table
    """
    try:
        if('username' not in login_session):
            login_session['username'] = "Admin_User"
        newUser = User(name=login_session['username'], email=login_session[
            'email'], picture=login_session['picture'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        logger.info("Added new user into User Table %s " % user.id)
        return user.id
    except:
        session.rollback()
    finally:
        session.close()


def getUserInfo(user_id):
    """
    Fetch User data or object using User Id
    """
    logger.info("Inside getUserInfo(), Get user data using id %s " % user_id)
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    Fetch User id using User email id
    """
    try:
        logger.info("Inside getUserID(), Get user id for username %s " % email)
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/')
@app.route('/catalog/')
def showCatalogApp():
    """
    Home page to Catalog Application
    Displays all the Categories and Items
    """
    catalogs = session.query(Catalog).all()
    items = session.query(Item, Catalog).join(Catalog).filter(
        Catalog.id == Item.catalog_id).order_by(Item.date.desc()).limit(10)
    logger.info("Inside showCatalogApp(), Return catalog.html - Home page")
    return render_template('catalog.html', catalogs=catalogs, items=items,
                           currentPage='catalog')


@app.route('/catalog/JSON')
def showCatalogJSON():
    """
    Returns the JSON values for the Categories
    """
    catalogs = session.query(Catalog).all()
    logger.info("""Inside showCatalogJSON(), Returns JSON
                values for all categories""")
    return jsonify(catalogs=[c.serialize for c in catalogs])


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCatalog():
    """
    Adds a new Category to the Catalog application
    """
    # First check the user state, if key <username> is in session
    if 'username' not in login_session:
        flash("To create one category you must be logged in")
        # If user is not logged will be redirected to login page
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            newCatalog = Catalog(name=request.form['name'],
                                 user_id=login_session['user_id'])
            session.add(newCatalog)
            session.commit()
            flash("{} successfully added to Catalogs".format(newCatalog.name))
            logger.info("Added new catalog")
            return redirect(url_for('showCatalogApp'))
        else:
            flash("Cannot create an empty category")
            return render_template('newcatalog.html')
    else:
        return render_template('newcatalog.html', currentPage='newcatalog')


@app.route('/catalog/<int:catalog_id>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_id):
    """
    To edit/modify an exiting Category in Catalog
    """
    # To edit one category user must be logged in & be the category creator
    if 'username' not in login_session:
        flash("To edit a category you must be logged in")
        return redirect('/login')
    else:
        catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        editedCatalog = catalog.name
    if request.method == 'POST':
        if request.form['name']:
            catalog.name = request.form['name']
            session.add(catalog)
            session.commit()
            flash("Catalog {} successfully edited to {}".format(editedCatalog,
                                                                catalog.name))
            logger.info("Edited existing catalog %s " % catalog.name)
            return redirect(url_for('showCatalogApp'))
        else:
            # If user doesn't edit specific category msg below is displayed
            flash("Nothing Changed")
            # Redirecting the user to respective category page
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        return render_template('editcatalog.html', catalog=catalog,
                               currentPage='editcatalog')


@app.route('/catalog/<int:catalog_id>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalog_id):
    """
    To delete an existing Category from the Catalog
    """
    # To delete one category user must be logged in & be the category creator
    if 'username' not in login_session:
        flash("To delete a category you must be logged in")
        return redirect('/login')
    else:
        catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        deletedCatalog = catalog.name
    if catalog.user_id != login_session['user_id']:
        flash("You a not authorized to delete {} category".format(
            deletedCatalog))
        return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    if request.method == 'POST':
        session.delete(catalog)
        session.commit()
        flash("{} successfully deleted from Catalog".format(deletedCatalog))
        logger.info("Deleting a catalog %s " % deletedCatalog)
        return redirect(url_for('showCatalogApp'))
    else:
        return render_template('deletecatalog.html', catalog=catalog,
                               currentPage='deletecatalog')


@app.route('/catalog/<int:catalog_id>/items/')
def showCatalogItems(catalog_id):
    """
    Display all the items under a specific Category
    """
    catalogs = session.query(Catalog).all()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items_catalog = session.query(Item).filter_by(catalog_id=catalog_id).all()
    logger.info("Inside showCatalogItems, Show all items inside catalog")
    return render_template('catalogitem.html', catalogs=catalogs,
                           catalog=catalog, items=items_catalog,
                           currentPage='catalogitem')


@app.route('/catalog/<int:catalog_id>/items/JSON')
def catalogItemsJSON(catalog_id):
    """
    returns the JSON values for all items under a Category
    """
    catalogItems = session.query(Item).filter_by(catalog_id=catalog_id).all()
    logger.info("JSON values for a catalog and it's items")
    return jsonify(catalogItems=[c.serialize for c in catalogItems])


@app.route('/catalog/<int:catalog_id>/<int:item_id>/JSON')
def itemJSON(catalog_id, item_id):
    """
    Implementation of JSON endpoint for an
    item present inside a category
    """
    item = session.query(Item).filter_by(id=item_id).one()
    logger.info("JSON values for a specific item")
    return jsonify(item=[item.serialize])


@app.route('/catalog/<int:catalog_id>/<int:item_id>/')
def showCatalogItemInfo(catalog_id, item_id):
    """
    Returns the description of an item chosen
    """
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    logger.info("Displaying catalog item description")
    return render_template('catalogiteminfo.html', catalog=catalog,
                           item=item, currentPage='catalogiteminfo')


@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editCatalogItem(catalog_id, item_id):
    """
    Edit/modify a category item
    """
    if 'username' not in login_session:
        flash("To edit an item you must be logged in")
        return redirect('/login')
    else:
        catalogs = session.query(Catalog).all()
        catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        item = session.query(Item).filter_by(id=item_id).one()
        editedItem = item.title
    if request.method == 'POST':
        if item.user_id != login_session['user_id']:
            flash("You a not authorized to edit this item")
            return render_template('editcatalogitem.html', item=item,
                                   catalogs=catalogs, catalog=catalog)
        if request.form['title']:
            item.title = request.form['title']
        if request.form['description']:
            item.description = request.form['description']
            item.catalog_id = catalog.id
            session.add(item)
            session.commit()
            flash("{} successfully edited".format(editedItem))
            logger.info("Editing the catalog item %s " % editedItem)
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
        else:
            flash("Nothing Changed")
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        return render_template('editcatalogitem.html', catalogs=catalogs,
                               catalog=catalog, item=item,
                               currentPage='editcatalogitem')


@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteCatalogItem(catalog_id, item_id):
    """
    Deletes an item from the Category
    """
    if 'username' not in login_session:
        flash("To delete an item you must be logged in")
        return redirect('/login')
    else:
        catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        itemToDelete = session.query(Item).filter_by(id=item_id).one()
        deletedItem = itemToDelete.title

    if itemToDelete.user_id != login_session['user_id']:
        flash("You a not authorized to delete this item")
        return redirect(url_for('showCatalogItemInfo',
                                catalog_id=catalog.id,
                                item_id=itemToDelete.id))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("{} successfully deleted".format(deletedItem))
        logger.info("Deleting a catalog item %s " % deletedItem)
        return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        return render_template('catalogiteminfo.html', catalog=catalog,
                               item=itemToDelete)


@app.route('/catalog/item/new/', methods=['GET', 'POST'])
def newItem():
    """
    Adds a new item under a Category
    """
    if 'username' not in login_session:
        flash("To create a new item you must be logged in")
        return redirect('/login')
    else:
        catalogs = session.query(Catalog).all()
    if request.method == 'POST':
        catalog = session.query(Catalog).filter_by(
            name=request.form['category']).one()
        if(
           request.form['title'] and
           request.form['category'] and
           request.form['description']):
            newItem = Item(title=request.form['title'],
                           description=request.form['description'],
                           catalog_id=catalog.id,
                           user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            flash("{} successfully added to {}".format(newItem.title,
                                                       catalog.name))
            logger.info("Added new item to catalog %s " % newItem.title)                                           
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
        else:
            flash("Couldn't create new Catalog Item")
            return render_template('newcatalogitem.html', catalog=catalog)

    else:
        return render_template('newcatalogitem.html', catalogs=catalogs,
                               currentPage='newcatalogitem')


if __name__ == '__main__':
    """
    Application execution point and port configuration
    """
    logger.info("ITEM CATALOG APPLICATION LOGS")
    app.secret_key = 'super_secret_key'
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=8000)
