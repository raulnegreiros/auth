import json
import os
import uuid
import re
import time
import binascii

from flask import Flask
from flask import request
from flask import make_response as fmake_response
# from flask_cors import CORS, cross_origin

import pymongo

from pbkdf2 import crypt
import jwt

import requests

from conf import loadconf, getConfValue
import kongUtils
from CollectionManager import CollectionManager

app = Flask(__name__)
# CORS(app)
app.url_map.strict_slashes = False

def make_response(payload, status):
    resp = fmake_response(payload, status)
    resp.headers['content-type'] = 'application/json'
    return resp

collection = CollectionManager('auth').getCollection('users')

#create index to optimize queries and enforce fields uniqueness
collection.create_index([('username', pymongo.ASCENDING)], name='username_index', unique=True)
collection.create_index([('email', pymongo.ASCENDING)], name='email_index', unique=True)

def formatResponse(status, message=None):
    payload = None
    if message:
        payload = json.dumps({ 'message': message, 'status': status})
    elif status >= 200 and status < 300:
        payload = json.dumps({ 'message': 'ok', 'status': status})
    else:
        payload = json.dumps({ 'message': 'Request failed', 'status': status})

    return make_response(payload, status);

@app.route('/', methods=['POST'])
def authenticate():
    if request.mimetype != 'application/json':
        return formatResponse(400, 'invalid mimetype')

    try:
        authData = json.loads(request.data)
    except ValueError:
        return formatResponse(400, 'malformed JSON')

    if 'username' not in authData.keys():
        return formatResponse(400, 'missing username')
    if 'passwd' not in authData.keys():
        return formatResponse(400, 'missing passwd')

    user = collection.find_one({'username' : authData['username'].lower()}, {"_id" : False})
    if user is None:
        return formatResponse(401, 'not authorized') #should not give hints about authentication problems
    
    if user['hash'] == crypt(authData['passwd'], user['salt'], 1000).split('$').pop():
        tokenExpiration = getConfValue('tokenExpiration')
        
        claims = {
            'iss': user['key'],
            'iat': int(time.time()),
            'exp': int(time.time() + tokenExpiration),

            #generate a random string as nonce
            'jti' : binascii.b2a_hex(os.urandom(16)),
            'service': user['service'],
            'username': user['username']
        }

        if 'name' in user.keys():
            claims['name'] = user['name']
        if 'email' in user.keys():
            claims['email'] = user['email']

        if 'profile' in user.keys():
            claims['profile'] = user['profile']
        else:
            claims['profile'] = 'user'

        encoded = jwt.encode(claims, user['secret'], algorithm='HS256')
        return make_response(json.dumps({'jwt': encoded}), 200)

    return formatResponse(401, 'not authorized')

class ParseError(Exception):
    """ Thrown indicating that an invalid user representation has been given """

    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

def checkUser(user):
    if 'username' not in user.keys() or len(user['username']) == 0:
        raise ParseError('Missing username')
    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise ParseError('Invalid username, only lowercase alhpanumeric and underscores allowed')

    if 'passwd' not in user.keys() or len(user['passwd']) == 0:
        raise ParseError('Missing passwd')

    if 'service' not in user.keys() or len(user['service']) == 0:
        raise ParseError('Missing service')
    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise ParseError('Invalid username, only alhpanumeric and underscores allowed')

    if 'email' not in user.keys() or len(user['email']) == 0:
        raise ParseError('Missing email')
    if re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', user['email']) is None:
        raise ParseError('Invalid email address')

    if 'name' not in user.keys() or len(user['name']) == 0:
        raise ParseError("Missing user's name (full name)")

    return user

# should have restricted access
@app.route('/user', methods=['GET'])
def listUsers():
    query={}
    if len(request.args) > 0:
        if 'username' in request.args:
            query['username'] = request.args['username']
        if 'id' in request.args:
            query['id'] = request.args['id']

    userList = []
    fieldFilter = {'_id': False, 'salt': False, 'hash': False, 'secret': False, 'key': False, 'kongid': False }
    for d in collection.find(query, fieldFilter):
        userList.append(d)

    if (len(userList) == 0) and (len(query) > 0):
        return formatResponse(404, "No users matching the criteria were found")

    return make_response(json.dumps({ "users" : userList}), 200)

# should have restricted access
@app.route('/user', methods=['POST'])
def createUser():
    if request.mimetype != 'application/json':
        return formatResponse(400, 'invalid mimetype')

    try:
        authData = json.loads(request.data)
    except ValueError:
        return formatResponse(400, 'malformed JSON')
    authData['id'] = str(uuid.uuid4())
    try:
        checkUser(authData)
    except ParseError as e:
        return formatResponse(400, str(e))

    if collection.find_one({'username' : authData['username']}, {"_id" : False}):
        return formatResponse(400, 'user already exists')

    if collection.find_one({'email' : authData['email']}, {"_id" : False}):
        return formatResponse(400, 'email already in use')

    authData['salt'] = os.urandom(8).encode('hex')
    authData['hash'] = crypt(authData['passwd'], authData['salt'], 1000).split('$').pop()

    kongData = kongUtils.configureKong(authData['username'])
    if kongData is None:
        return formatResponse(500, 'failed to configure verification subsystem')
    authData['secret'] = kongData['secret']
    authData['key'] = kongData['key']
    authData['kongid'] = kongData['kongid']
    del authData['passwd']
    collection.insert_one(authData.copy())
    result = {
        "username": authData['username'],
        "service": authData['service'],
        "id": authData['id']
    }
    return make_response(json.dumps({"user": result, "message": "user created"}), 200)

# should have restricted access
@app.route('/user/<userid>', methods=['GET'])
def getUser(userid):
    query = {'id': userid}
    fieldFilter = {'_id': False, 'salt': False, 'hash': False, 'secret': False, 'key': False, 'kongid': False }
    old_user = collection.find_one(query, fieldFilter)
    if old_user is None:
        return formatResponse(404, 'Unknown user id')

    return make_response(json.dumps({"user": old_user}), 200)

# should have restricted access
@app.route('/user/<userid>', methods=['PUT'])
def updateUser(userid):
    if request.mimetype != 'application/json':
        return formatResponse(400, 'invalid mimetype')

    query = {'id': userid}
    old_user = collection.find_one(query, {"_id" : False})
    if old_user is None:
        return formatResponse(404, 'Unknown user id')

    try:
        authData = json.loads(request.data)
    except ValueError:
        return formatResponse(400, 'malformed JSON')

    if 'id' not in authData.keys():
        authData['id'] = userid
    elif authData['id'] != userid:
        return formatResponse(400, "user ID can't be updated")

    try:
        checkUser(authData)
    except ParseError as e:
        return formatResponse(400, str(e))

    if old_user['username'] != authData['username']:
        return formatResponse(400, "usernames can't be updated")

    #verify if the email is in use by another user
    anotherUser = collection.find_one({'email' : authData['email']}, {"_id" : False})
    if anotherUser is not None:
        if anotherUser['id'] != old_user['id']:
            return formatResponse(400, 'email already in use')

    authData['salt'] = os.urandom(8).encode('hex')
    authData['hash'] = crypt(authData['passwd'], authData['salt'], 1000).split('$').pop()

    kongData = kongUtils.configureKong(authData['username'])
    if kongData is None:
        return formatResponse(500, 'failed to configure verification subsystem')

    if 'kongid' in old_user.keys():
        kongUtils.revokeKongSecret(old_user['username'], old_user['kongid'])
    authData['secret'] = kongData['secret']
    authData['key'] = kongData['key']
    authData['kongid'] = kongData['kongid']
    del authData['passwd']
    collection.replace_one(query, authData.copy())
    return formatResponse(200)

@app.route('/user/<userid>', methods=['DELETE'])
def removeUser(userid):
    query = {'id': userid}
    old_user = collection.find_one(query, {'id': False})
    if old_user is None:
        return formatResponse(404, 'Unknown user id')

    try:
        kongUtils.removeFromKong(old_user['username'])
    except:
        return formatResponse(500, "Failed to configure verification subsystem")

    collection.delete_one(query)
    return formatResponse(200, "User removed")


# should have restricted access
@app.route('/user/search', methods=['GET'])
def searchUser():
    term = None
    if len(request.args) > 0:
        if 'q' in request.args:
            term = request.args['q']
    
    if not term:
        return formatResponse(400, 'No query given')

    #TODO: define a minimum and maximun search term len
    if (len(term) < 2):
        return formatResponse(400, 'The search term must have at least 3 characters')

    if re.match(r'^[a-zA-Z0-9_@.]+$', term) is None:
        return formatResponse(400, 'Invalid search term. only alhpanumeric, AT, dots and underscores allowed')
    
    term = term.lower()
    userList = []

    query = {"$or":[ {"name": {"$regex": re.compile(term, re.IGNORECASE)}} , {"username": {"$regex": term} }, {"email": {"$regex": term} }]}
    fieldFilter = {'_id': False, 'salt': False, 'hash': False, 'secret': False, 'key': False, 'kongid': False }
    for d in collection.find(query, fieldFilter):
        userList.append(d)

    if (len(userList) == 0):
        return formatResponse(404, "No users matching the criteria were found")

    return make_response(json.dumps({ "users" : userList}), 200)

# should have restricted access for outside the aplication
@app.route('/revoke', methods=['DELETE'])
def revokeAll():
    #for all user, create a new secret and delete the old one
    for user in collection.find():
        kongData = kongUtils.configureKong(user['username'])
        if kongData is None:
            return 'failed to configure verification subsystem'
        
        #revoke the old key
        if 'kongid' in user.keys():
            kongUtils.revokeKongSecret(user['username'], user['kongid'])
        
        user['secret'] = kongData['secret']
        user['key'] = kongData['key']
        user['kongid'] = kongData['kongid']
        collection.replace_one( {'_id': user['_id']} , user.copy())
    return formatResponse(200)

if __name__ == '__main__':
    loadconf()
    kongUtils.kong = getConfValue('kongURL')
    app.run(host='0.0.0.0', threaded=True)
