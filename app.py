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
from pymongo import MongoClient

from pbkdf2 import crypt
import jwt

import requests
from requests import ConnectionError

app = Flask(__name__)
# CORS(app)
app.url_map.strict_slashes = False

def make_response(payload, status):
    resp = fmake_response(payload, status)
    resp.headers['content-type'] = 'application/json'
    return resp

class CollectionManager:
    def __init__(self, database, server='mongodb', port=27017):
        self.client = None
        self.collection = None
        self.database = database
        self.server = server
        self.port = port

    def getDB(self):
        if not self.client:
            self.client = MongoClient(self.server, self.port)
        return self.client[self.database]

    def getCollection(self, collection):
        return self.getDB()[collection]

    def __call__(self, collection):
        return self.getCollection(collection)

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
        claims = {
            'iss': user['key'],
            'iat': int(time.time()),
            #TODO: ativate exp time (this feature causes UX problems in the current version)
            #'exp': int(time.time() + tokenExpirationMinutes*60),

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

kong = 'http://kong:8001'
def configureKong(user):
    try:
        exists = False
        response = requests.post('%s/consumers' % kong, data={'username': user})
        if response.status_code == 409:
            exists = True
        elif not (response.status_code >= 200 and response.status_code < 300):
            print ("failed to set consumer: %d %s" % (response.status_code, response.reason))
            print (response.json())
            return None

        headers = {"content-type":"application/x-www-form-urlencoded"}
        response = requests.post('%s/consumers/%s/jwt' % (kong, user), headers=headers)
        if not (response.status_code >= 200 and response.status_code < 300):
            print ("failed to create key: %d %s" % (response.status_code, response.reason))
            print (response.json())
            return None

        reply = response.json()
        return { 'key': reply['key'], 'secret': reply['secret'] }
    except ConnectionError:
        print("Failed to connect to kong")
        return None

def removeFromKong(user):
    try:
        response = requests.delete("%s/consumers/%s" % (kong, user))
    except ConnectionError:
        print "Failed to connect to kong"
        raise

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
    fieldFilter = {'_id': False, 'salt': False, 'hash': False, 'secret': False, 'key': False }
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

    kongData = configureKong(authData['username'])
    if kongData is None:
        return formatResponse(500, 'failed to configure verification subsystem')
    authData['secret'] = kongData['secret']
    authData['key'] = kongData['key']
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
    fieldFilter = {'_id': False, 'salt': False, 'hash': False, 'secret': False, 'key': False }
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

    kongData = configureKong(authData['username'])
    if kongData is None:
        return formatResponse(500, 'failed to configure verification subsystem')
    authData['secret'] = kongData['secret']
    authData['key'] = kongData['key']
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
        removeFromKong(old_user['username'])
    except:
        return formatResponse(500, "Failed to configure verification subsystem")

    collection.delete_one(query)
    return formatResponse(200, "User removed")

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)
