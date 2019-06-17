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

import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Connect to itemcatalog database and create database session
engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Client id from authentication
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# FB connect authentication
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = '''https://graph.facebook.com/oauth/access_token?grant_type=
    fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s''' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = '''https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,
    email''' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
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
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = "<h6><strong>Redirecting...</strong></h6>"
    flash("Welcome {} you are now logged in".format(login_session['username']))
    return output


# FB Disconnect session
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Login to Catalog
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    # Add to client session the state string in order to preven anti-forgery
    login_session['state'] = state
    return render_template('login.html', currentPage='login', STATE=state)


# Disconnect from FB or Google and clear the session
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        login_session.clear()
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalogApp'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalogApp'))


# Google authentication
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
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
    result = json.loads(h.request(url, 'GET')[1])
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
    print(login_session)
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = "<h6><strong>Redirecting...</strong></h6>"
    flash("Welcome {} you are now logged in".format(login_session['username']))
    return output


# Google Disconnect
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
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


# Add new user to User Table in DB
def createUser(login_session):
    try:
        if('username' not in login_session):
            login_session['username'] = "Admin_User"
        newUser = User(name=login_session['username'], email=login_session[
            'email'], picture=login_session['picture'])
        session.add(newUser)
        session.commit()
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        return user.id
    except:
        session.rollback()
    finally:
        session.close()


# Get user info from DB
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Get user ID
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Show all categories in item catalog app
@app.route('/')
@app.route('/catalog/')
def showCatalogApp():
    catalogs = session.query(Catalog).all()
    items = session.query(Item, Catalog).join(Catalog).filter(
        Catalog.id == Item.catalog_id).order_by(Item.date.desc()).limit(10)
    return render_template('catalog.html', catalogs=catalogs, items=items,
                           currentPage='catalog')


# Returns JSON value for catalog app
@app.route('/catalog/json')
def showCatalogJSON():
    catalogs = session.query(Catalog).all()
    return jsonify(restaurants=[c.serialize for c in catalogs])


# Adding a new Catalog to the Item catalog application
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCatalog():
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
            return redirect(url_for('showCatalogApp'))
        else:
            flash("Cannot create an empty category")
            return render_template('newcatalog.html')
    else:
        return render_template('newcatalog.html', currentPage='newcatalog')


# Editing a catalog
@app.route('/catalog/<int:catalog_id>/edit/', methods=['GET', 'POST'])
def editCatalog(catalog_id):
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
            return redirect(url_for('showCatalogApp'))
        else:
            # If user doesn't edit specific category msg below is displayed
            flash("Nothing Changed")
            # Redirecting the user to respective category page
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        return render_template('editcatalog.html', catalog=catalog,
                               currentPage='editcatalog')


# Delete a catalog
@app.route('/catalog/<int:catalog_id>/delete/', methods=['GET', 'POST'])
def deleteCatalog(catalog_id):
    # To delete one category user must be logged in & be the category creator
    if 'username' not in login_session:
        flash("To delete a category you must be logged in")
        return redirect('/login')
    else:
        catalog = session.query(Catalog).filter_by(id=catalog_id).one()
        print(catalog.user_id)
        deletedCatalog = catalog.name
    if catalog.user_id != login_session['user_id']:
        print("User Id %s" % catalog.user_id)
        flash("You a not authorized to delete {} category".format(
            deletedCatalog))
        return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    if request.method == 'POST':
        session.delete(catalog)
        session.commit()
        flash("{} successfully deleted from Catalog".format(deletedCatalog))
        return redirect(url_for('showCatalogApp'))
    else:
        return render_template('deletecatalog.html', catalog=catalog,
                               currentPage='deletecatalog')


# Show Catalog items
@app.route('/catalog/<int:catalog_id>/items/')
def showCatalogItems(catalog_id):
    catalogs = session.query(Catalog).all()
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    items_catalog = session.query(Item).filter_by(catalog_id=catalog_id).all()
    return render_template('catalogitem.html', catalogs=catalogs,
                           catalog=catalog, items=items_catalog,
                           currentPage='catalogitem')


# Returns a Catalog Items JSON value
@app.route('/catalog/<int:catalog_id>/items/JSON')
def catalogItemsJSON(catalog_id):
    catalogItems = session.query(Item).filter_by(catalog_id=catalog_id).all()
    return jsonify(catalogItems=[c.serialize for c in catalogItems])


# Choosing an item in category returns the information of the item
@app.route('/catalog/<int:catalog_id>/<int:item_id>/')
def showCatalogItemInfo(catalog_id, item_id):
    catalog = session.query(Catalog).filter_by(id=catalog_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('catalogiteminfo.html', catalog=catalog,
                           item=item, currentPage='catalogiteminfo')


# Editing an item inside category
@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editCatalogItem(catalog_id, item_id):
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
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
        else:
            flash("Nothing Changed")
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        print('edit catalog page')
        return render_template('editcatalogitem.html', catalogs=catalogs,
                               catalog=catalog, item=item,
                               currentPage='editcatalogitem')


# Deleting an item from a category
@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def deleteCatalogItem(catalog_id, item_id):
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
        return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
    else:
        return render_template('catalogiteminfo.html', catalog=catalog,
                               item=itemToDelete)


# Add new item in a category
@app.route('/catalog/item/new/', methods=['GET', 'POST'])
def newItem():
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
            return redirect(url_for('showCatalogItems', catalog_id=catalog.id))
        else:
            flash("Couldn't create new Catalog Item")
            return render_template('newcatalogitem.html', catalog=catalog)

    else:
        return render_template('newcatalogitem.html', catalogs=catalogs,
                               currentPage='newcatalogitem')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=8000)
