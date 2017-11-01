#!/usr/bin/python3
# This file contains the available endpoints
# functions here focus on extract data from HTTP requests
# and format responses and errors to JSON
# These functions should be as smaller as possible
# most of the input validation is done on the controllers

from flask import Flask
from flask import request
import json

import conf
import controller.CRUDController as crud
import controller.RelationshipController as rship
import controller.PDPController as pdpc
import controller.AuthenticationController as auth
import controller.ReportController as reports
import kongUtils as kong
from database.flaskAlchemyInit import app, db, formatResponse, \
                        HTTPRequestError, make_response, loadJsonFromRequest
from database.Models import MVUserPermission, MVGroupPermission
import database.Cache as cache


# Authenticion endpoint
@app.route('/', methods=['POST'])
def authenticate():
    try:
        authData = loadJsonFromRequest(request)
        jwt = auth.authenticate(db.session, authData)
        return make_response(json.dumps({'jwt': jwt}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


# User CRUD
@app.route('/user', methods=['POST'])
def createUser():
    try:
        authData = loadJsonFromRequest(request)

        # Create user
        newUser = crud.createUser(db.session, authData)

        # If no problems occur to create user (no exceptions), configure kong
        kongData = kong.configureKong(newUser.username)
        if kongData is None:
            return formatResponse(500,
                                  'failed to configure verification subsystem')
        newUser.secret = kongData['secret']
        newUser.key = kongData['key']
        newUser.kongId = kongData['kongid']

        db.session.add(newUser)
        db.session.commit()
        return make_response(json.dumps({
                                        "user": newUser.safeDict(),
                                        "message": "user created"
                                        }), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user', methods=['GET'])
def listUsers():
    try:
        users = crud.searchUser(
            db.session,
            # Optional search filters
            request.args['username'] if 'username' in request.args else None
        )
        usersSafe = list(map(lambda u: u.safeDict(), users))
        return make_response(json.dumps({"users": usersSafe}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user/<user>', methods=['GET'])
def getUser(user):
    try:
        user = crud.getUser(db.session, user)
        return make_response(json.dumps({"user": user.safeDict()}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user/<user>', methods=['PUT'])
def updateUser(user):
    try:
        authData = loadJsonFromRequest(request)
        oldUser = crud.updateUser(db.session, userid, authData)

        # Create a new kong secret and delete the old one
        kongData = kong.configureKong(oldUser.username)
        if kongData is None:
            return formatResponse(500,
                                  'failed to configure verification subsystem')

        kong.revokeKongSecret(oldUser.username, oldUser.kongId)
        oldUser.secret = kongData['secret']
        oldUser.key = kongData['key']
        oldUser.kongid = kongData['kongid']
        db.session.add(oldUser)
        db.session.commit()
        return formatResponse(200)

    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/user/<user>', methods=['DELETE'])
def removeUser(user):
    try:
        old_user = crud.getUser(db.session, user)
        kong.removeFromKong(old_user.username)
        crud.deleteUser(db.session, user)
        MVUserPermission.refresh()
        MVGroupPermission.refresh()
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
        return make_response(json.dumps({
                                        "status": 200,
                                        "id": newPerm.id
                                        }), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/permission', methods=['GET'])
def listPermissions():
    try:
        permissions = crud.searchPerm(
            db.session,

            # search filters
            request.args['path'] if 'path' in request.args else None,
            request.args['method'] if 'method' in request.args else None,
            request.args['permission']
            if 'permission' in request.args else None
        )
        permissionsSafe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({
                                        "permissions": permissionsSafe
                                        }), 200)
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
        MVUserPermission.refresh()
        MVGroupPermission.refresh()
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
        return make_response(json.dumps({
                                        "status": 200,
                                        "id": newGroup.id
                                        }), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/group', methods=['GET'])
def listGroup():
    try:
        groups = crud.searchGroup(
            db.session,

            # search filters
            request.args['name'] if 'name' in request.args else None
        )
        groupsSafe = list(map(lambda p: p.safeDict(), groups))
        return make_response(json.dumps({"groups": groupsSafe}), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['GET'])
def getGroup(group):
    try:
        group = crud.getGroup(db.session, group)
        return make_response(json.dumps(group.safeDict()), 200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['PUT'])
def updateGroup(group):
    try:
        groupData = loadJsonFromRequest(request)
        crud.updateGroup(db.session, group, groupData)
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/group/<group>', methods=['DELETE'])
def deleteGroup(group):
    try:
        crud.deleteGroup(db.session, group)
        MVGroupPermission.refresh()
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/usergroup/<user>/<group>', methods=['POST', 'DELETE'])
def addUserToGroup(user, group):
    try:
        if request.method == 'POST':
            rship.addUserGroup(db.session, user, group)
        else:
            rship.removeUserGroup(db.session, user, group)
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/grouppermissions/<group>/<permissionid>',
           methods=['POST', 'DELETE'])
def addGroupPermission(group, permissionid):
    try:
        if request.method == 'POST':
            rship.addGroupPermission(db.session, group, int(permissionid))
        else:
            rship.removeGroupPermission(db.session, group, int(permissionid))
        MVGroupPermission.refresh()
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pap/userpermissions/<user>/<permissionid>',
           methods=['POST', 'DELETE'])
def addUserPermission(user, permissionid):
    try:
        if request.method == 'POST':
            rship.addUserPermission(db.session, user, int(permissionid))
        else:
            rship.removeUserPermission(db.session, user, int(permissionid))
        MVUserPermission.refresh()
        db.session.commit()
        return formatResponse(200)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)


@app.route('/pdp', methods=['POST'])
def pdpRequest():
    try:
        pdpData = loadJsonFromRequest(request)
        veredict = pdpc.pdpMain(db.session, pdpData)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        return make_response(json.dumps({
                                        "decision": veredict,
                                        "status": "ok"
                                        }), 200)


#  Reports endpoints
@app.route('/pap/user/<user>/directpermissions', methods=['GET'])
def getUserDiectPermissions(user):
    try:
        permissions = reports.getUserDiectPermissions(db.session, user)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        permissionsSafe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({
                                        "permissions": permissionsSafe
                                        }), 200)


@app.route('/pap/user/<user>/allpermissions', methods=['GET'])
def getAllUserPermissions(user):
    try:
        permissions = reports.getAllUserPermissions(db.session, user)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        permissionsSafe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({
                                        "permissions": permissionsSafe
                                        }), 200)


@app.route('/pap/user/<user>/groups', methods=['GET'])
def getUserGrups(user):
    try:
        groups = reports.getUserGrups(db.session, user)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        groupsSafe = list(map(lambda p: p.safeDict(), groups))
        return make_response(json.dumps({"groups": groupsSafe}), 200)


@app.route('/pap/group/<group>/permissions', methods=['GET'])
def getGroupPermissions(group):
    try:
        permissions = reports.getGroupPermissions(db.session, group)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        permissionsSafe = list(map(lambda p: p.safeDict(), permissions))
        return make_response(json.dumps({"permissions": permissionsSafe}), 200)


@app.route('/pap/group/<group>/users', methods=['GET'])
def getGroupUsers(group):
    try:
        users = reports.getGroupUsers(db.session, group)
    except HTTPRequestError as err:
        return formatResponse(err.errorCode, err.message)
    else:
        usersSafe = list(map(lambda p: p.safeDict(), users))
        return make_response(json.dumps({"users": usersSafe}), 200)


@app.route('/admin/dropcache', methods=['DELETE'])
def dropCache():
    cache.deleteKey()
    return formatResponse(200)


if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)
