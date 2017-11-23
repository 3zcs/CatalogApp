#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import request, url_for, jsonify, json, make_response, flash
from flask import Flask, render_template, redirect
from flask import session as login_session
import random
import string
from sqlalchemy import create_engine
from database_setup import Base, Category, Item, User
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']  # noqa
APPLICATION_NAME = 'Catalog App'

engine = create_engine('sqlite:///category.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/<int:category_id>/')
def Index(category_id=0):
    category = session.query(Category).all()
    if category_id != 0:
        items = session.query(Item).filter_by(category_id=category_id)
    else:
        items = session.query(Item).all()
    return render_template('catalog.html', category=category,
                           c_id=category_id, items=items,
                           loged=isUserLoged())
# main page, show list of category and items


@app.route('/delete/<int:item_id>/', methods=['POST'])
def Delete_item(item_id):
    if not isUserLoged():
        return redirect(url_for('Index'))
    if request.form['submit'] == 'Delete' and isUserAuthraized(item_id):
        return redirect(url_for('confirm', item_id=item_id))
    elif request.form['submit'] == 'Confirmed' and isUserAuthraized(item_id):
        item = session.query(Item).filter_by(id=item_id).one()
        session.delete(item)
        session.commit()
        return redirect(url_for('Index')) 
    elif isUserAuthraized(item_id):
        return redirect(url_for('Update_Item', item_id=item_id))
    else:
        redirect(url_for('Index'))
# route to delete or edit,cancel take you to main page


@app.route('/item/<int:item_id>/')
def ShowItem(item_id):
    output = ''
    item = session.query(Item).filter_by(id=item_id).one()

    return render_template('item.html', item=item, c_id=item.id,
                           loged=isUserLoged() and isUserAuthraized(item_id))
# show item with option delete or edit for loged user


@app.route('/add_item/<int:category_id>')
def Add_Item(category_id):
    if not isUserLoged():
        return redirect(url_for('Index'))
    category = session.query(Category).filter_by(id=category_id).one()
    return render_template('add_item.html', category=category,
                           loged=isUserLoged())
# add item for loged user


@app.route('/add_item/<int:category_id>', methods=['POST'])
def New_Item(category_id):
    if not isUserLoged():
        return redirect(url_for('Index'))
    category = session.query(Category).all()
    if request.form['submit'] == 'save':
        name = request.form['name']
        description = request.form['description']
        session.add(Item(name=name, description=description,
                    category_id=category_id,
                    user_id=getUserID(login_session['email'])))
        session.commit()

    return redirect(url_for('Index'))
# receive post from add_item and handle it


@app.route('/confirm/<int:item_id>')
def confirm(item_id):
    if not isUserLoged() or not isUserAuthraized(item_id):
        return redirect(url_for('Index'))
    return render_template('confirm.html', item_id=item_id,
                           loged=isUserLoged())
# confirm to delete


@app.route('/update/<int:item_id>', methods=['POST'])
def Update(item_id):
    if not isUserLoged() and not isUserAuthraized(item_id):
        return redirect(url_for('Index'))
    if request.form['submit'] == 'save':
        item = session.query(Item).filter_by(id=item_id).one()
        item.name = request.form['name']
        item.description = request.form['description']
        session.add(item)
        session.commit()

    return redirect(url_for('Index'))
# update post from Update_Item


@app.route('/update_item/<int:item_id>')
def Update_Item(item_id):
    if not isUserLoged() and not isUserAuthraized(item_id):
        return redirect(url_for('Index'))
    item = session.query(Item).filter_by(id=item_id).one()
    i_id = item.category_id
    category = \
        session.query(Category).filter_by(id=item.category_id).one()

    return render_template('update_item.html', category=category,
                           item=item, loged=isUserLoged())
# show item with option to edit or cancel


def isUserLoged():
    return 'gplus_id' in login_session
# check is user loged or not

def isUserAuthraized(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    if item is None:
        item = 0
    return item.user_id == getUserID(login_session['email'])
# check is user authraized or not


@app.route('/login/')
def Login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))  # noqa
    login_session['state'] = state

    return render_template('login.html', STATE=state)
# login page with google sing-in


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = \
            make_response(json.dumps('Failed to revoke token for given user.', 400))  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/<int:item_id>/json/')
def Json_item(item_id):

    category = session.query(Category).all()
    itemList = []
    item = session.query(Item).filter_by(id=item_id).one()
    new_item = {'name': i.name, 'id': i.id,
                'description': i.description,
                'category': category.name}
    itemList.append(new_item)
    result = json.dumps(itemList)
    response = make_response(json.dumps(catalogList))
    response.headers['content-type'] = 'application/json'
    return response
# Show one item as json


@app.route('/json/')
def Json():
    catalogList = []

    category = session.query(Category).all()
    for c in category:
        itemList = []
        item = session.query(Item).filter_by(id=c.id).all()
        for i in item:
            new_item = {'name': i.name, 'id': i.id,
                        'description': i.description}
            itemList.append(new_item)
        category = {'Items': itemList, 'name': c.name, 'id': c.id}
        catalogList.append(category)
    result = json.dumps(catalogList)
    response = make_response(json.dumps(catalogList))
    response.headers['content-type'] = 'application/json'
    return response
# show full catalog as json


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')  # noqa
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps('Failed to upgrade the authorization code.'), 401)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
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
        response = \
            make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps("Token's client ID does not match app's."), 401)  # noqa
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('Current user is already connected.'), 200)  # noqa
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    if getUserID(login_session['email']) is None:
        createUser(login_session)

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def fill_database():
    session.query(Category).delete()
    Category1 = Category(name='Soccer')
    Category2 = Category(name='Basketball')
    Category3 = Category(name='Baseball')
    Category4 = Category(name='Frisbee')
    Category5 = Category(name='Snowboarding')
    session.add(Category1)
    session.add(Category2)
    session.add(Category3)
    session.add(Category4)
    session.add(Category5)
    session.commit()
# fill category list


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    fill_database()
    app.run(host='0.0.0.0', port=5000)

