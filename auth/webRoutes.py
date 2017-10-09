#!/usr/bin/python3
'''
 This file contains the available endpoints
 functions here focus on extract data from HTTP requests
 and format responses and errors to JSON
 These functions should be as smaller as possible
 most of the input validation is done on the controllers
'''

from flask import Flask
from flask import request
import json

import conf
import database.CRUDController as crud
import authentication as auth
import kongUtils as kong
from flaskAlchemyInit import app, db, formatResponse, HTTPRequestError, \
                             make_response, loadJsonFromRequest

#authenticion endpoint
@app.route('/', methods=['POST'])
def authenticate():
    try:
        authData = loadJsonFromRequest(request)
        if 'username' not in authData.keys() :  return formatResponse(400, 'missing username')
        if 'passwd' not in authData.keys()   :  return formatResponse(400, 'missing passwd')

        jwt = auth.authenticate(db.session, authData['username'], authData['passwd'])

        return make_response(json.dumps({'jwt': jwt}), 200)

    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

# User CRUD
@app.route('/user', methods=['POST'])
def createUser():
    try:
        authData = loadJsonFromRequest(request)

        #create user
        newUser = crud.createUser(db.session, authData)

        #if no problems occur to create user (no exceptions), configure kong
        kongData = kong.configureKong(newUser.username)
        if kongData is None:
            return formatResponse(500, 'failed to configure verification subsystem')
        newUser.secret = kongData['secret']
        newUser.key = kongData['key']
        newUser.kongId = kongData['kongid']

        db.session.add(newUser)
        db.session.commit()
        return make_response(json.dumps({"user": newUser.safeDict(), "message": "user created"}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/user', methods=['GET'])
def listUsers():
    try:
        users = crud.searchUser(db.session, \
            #filters
            request.args['username'] if 'username' in request.args else None
        )
        usersSafe = list(map(lambda u: u.safeDict(), users))
        return make_response(json.dumps({ "users" : usersSafe}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user/<userid>', methods=['GET'])
def getUser(userid):
    try:
        user = crud.getUser(db.session, int(userid))
        return make_response(json.dumps({"user": user.safeDict()}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

# should have restricted access
@app.route('/user/<userid>', methods=['PUT'])
def updateUser(userid):
    try:
        authData = loadJsonFromRequest(request)
        #update user fields
        oldUser = crud.updateUser(db.session, int(userid), authData)

        #create a new kong secret and delete the old one
        kongData = kong.configureKong(oldUser.username)
        if kongData is None:
            return formatResponse(500, 'failed to configure verification subsystem')

        kong.revokeKongSecret(oldUser.username, oldUser.kongId)
        oldUser.secret = kongData['secret']
        oldUser.key = kongData['key']
        oldUser.kongid = kongData['kongid']
        db.session.add(oldUser)
        db.session.commit()
        return formatResponse(200)

    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user/<userid>', methods=['DELETE'])
def removeUser(userid):
    try:
        old_user = crud.getUser(db.session, int(userid))
        kong.removeFromKong(old_user.username)
        crud.deleteUser(db.session, int(userid))
        db.session.commit()
        return formatResponse(200, "User removed")
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

# Permission CRUD
@app.route('/pap/permission', methods=['POST'])
def createPermission():
    try:
        permData = loadJsonFromRequest(request)
        newPerm = crud.createPerm(db.session, permData)
        db.session.add(newPerm)
        db.session.commit()
        return make_response(json.dumps({"status": 200, "id": newPerm.id}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/permission', methods=['GET'])
def listPermissions():
    try:
        permissions = crud.searchPerm(db.session, \
            #filters
            request.args['path'] if 'path' in request.args else None,
            request.args['method'] if 'method' in request.args else None,
            request.args['permission'] if 'permission' in request.args else None
        )
        permissionsSafe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({ "permissions" : permissionsSafe}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/permission/<permid>', methods=['GET'])
def getPermission(permid):
    try:
        perm = crud.getPerm(db.session, int(permid))
        return make_response(json.dumps(perm.safeDict()), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/permission/<permid>', methods=['PUT'])
def updatePermission(permid):
    try:
        permData = loadJsonFromRequest(request)
        crud.updatePerm(db.session, int(permid), permData)
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/permission/<permid>', methods=['DELETE'])
def deletePermission(permid):
    try:
        crud.getPerm(db.session, int(permid))
        crud.deletePerm(db.session, int(permid))
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

# Group CRUD
@app.route('/pap/group', methods=['POST'])
def createGroup():
    try:
        groupData = loadJsonFromRequest(request)
        newGroup = crud.createGroup(db.session, groupData)
        db.session.add(newGroup)
        db.session.commit()
        return make_response(json.dumps({"status": 200, "id": newGroup.id}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/group', methods=['GET'])
def listGroup():
    try:
        groups = crud.searchGroup(db.session, \
            #filters
            request.args['name'] if 'name' in request.args else None
        )
        groupsSafe = list(map(lambda p: p.safeDict(), groups))
        return make_response(json.dumps({ "groups" : groupsSafe}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/group/<groupId>', methods=['GET'])
def getGroup(groupId):
    try:
        group = crud.getGroup(db.session, int(groupId))
        return make_response(json.dumps(group.safeDict()), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/group/<groupId>', methods=['PUT'])
def updateGroup(groupId):
    try:
        groupData = loadJsonFromRequest(request)
        crud.updateGroup(db.session, int(groupId), groupData)
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

@app.route('/pap/group/<groupId>', methods=['DELETE'])
def deleteGroup(groupId):
    try:
        crud.getGroup(db.session, int(groupId))
        crud.deleteGroup(db.session, int(groupId))
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)
