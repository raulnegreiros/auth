#!/usr/bin/python3
# This script creates the initial groups, permissions and users

import binascii
import os
from pbkdf2 import crypt
import sqlalchemy

from database.flaskAlchemyInit import db
from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.Models import MVUserPermission, MVGroupPermission

import kongUtils as kong


def createUsers():
    predefusers = [
        {
            "name": "Admin (superuser)",
            "username": "admin",
            "service": "admin",
            "email": "admin@noemail.com",
            "profile": "admin",
            "passwd": "admin"
        }
    ]

    for user in predefusers:
        # check if the user already exist
        # if the user exist, chances are this scrip has been run before
        anotherUser = db.session.query(User.id) \
                                .filter_by(username=user['username']) \
                                .one_or_none()
        if anotherUser:
            print("That not the first container run. Skipping")
            exit(0)
        # mark the user as automatically created
        user['created_by'] = 0

        # hash the password
        user['salt'] = str(binascii.hexlify(os.urandom(8)), 'ascii')
        user['hash'] = crypt(user['passwd'],
                             user['salt'],
                             1000).split('$').pop()
        del user['passwd']
        newUser = User(**user)

        # configure kong shared secret
        kongData = kong.configureKong(newUser.username)
        if kongData is None:
            print('failed to configure verification subsystem')
            exit(-1)
        newUser.secret = kongData['secret']
        newUser.key = kongData['key']
        newUser.kongId = kongData['kongid']
        db.session.add(newUser)
    db.session.commit()


def createGroups():
    predefGroups = [
        {
            "name": "admin",
            "description": "Group with the highest access privilege"
        },
        {
            "name": "user",
            "description": "This groups can do anything, except manage users"
        }
    ]
    for g in predefGroups:
        # mark the group as automatically created
        g['created_by'] = 0
        group = Group(**g)
        db.session.add(group)
    db.session.commit()


# A utility function to create a permission dict
# so the List 'predefPerms' get less verbose
def permissionDictHelper(name, path, method, permission=PermissionEnum.permit):
    return {
        "name": name,
        "path":  path,
        "method": method,
        "permission": permission,
        "created_by": 0
    }


def createPermissions():
    predefPerms = [
                permissionDictHelper('all_template', "/template/(.*)", "(.*)"),
                permissionDictHelper('ro_template', "/template/(.*)", "GET"),
                permissionDictHelper('all_device', "/device/(.*)", "(.*)"),
                permissionDictHelper('ro_device', "/device/(.*)", "GET"),
                permissionDictHelper('all_flows', "/flows/(.*)", "(.*)"),
                permissionDictHelper('ro_flows', "/flows/(.*)", "GET"),
                permissionDictHelper('all_history', "/history/(.*)", "(.*)"),
                permissionDictHelper('ro_history', "/history/(.*)", "GET"),
                permissionDictHelper('all_metric', "/metric/(.*)", "(.*)"),
                permissionDictHelper('ro_metric', "/metric/(.*)", "GET"),
                permissionDictHelper('all_mashup', "/mashup/(.*)", "(.*)"),
                permissionDictHelper('ro_mashup', "/mashup/(.*)", "GET"),
                permissionDictHelper('all_user', "/auth/user/(.*)", "(.*)"),
                permissionDictHelper('ro_user', "/auth/user/(.*)", "GET"),
                permissionDictHelper('all_pap', "/pap/(.*)", "(.*)"),
                permissionDictHelper('ro_pap', "/pap/(.*)", "GET"),
                permissionDictHelper('ro_ca', "/ca/(.*)", "GET"),
                permissionDictHelper('wo_sign', "/sign/(.*)", "POST")
                ]

    for p in predefPerms:
        perm = Permission(**p)
        db.session.add(perm)
    db.session.commit()


def addUserGroups():
    predefUserGroup = [
        {
            "name": "admin",
            "groups": ["admin"]
        },
    ]

    for u in predefUserGroup:
        userId = User.getByNameOrID(u['name']).id
        for groupName in u['groups']:
            r = UserGroup(
                            user_id=userId,
                            group_id=Group.getByNameOrID(groupName).id
                        )
            db.session.add(r)
    db.session.commit()


def addPermissionsGroup():
    predefGroupPerm = [
        {
            "name": "admin",
            "permission": [
                    'all_template',
                    'all_device',
                    'all_flows',
                    'all_history',
                    'all_metric',
                    'all_mashup',
                    'all_user',
                    'all_pap',
                    'ro_ca',
                    'wo_sign'
            ]
        },
        {
            "name": "user",
            "permission": [
                    'all_template',
                    'all_device',
                    'all_flows',
                    'all_history',
                    'all_metric',
                    'all_mashup',
                    'ro_ca',
                    'wo_sign'
            ]
        }
    ]

    for g in predefGroupPerm:
        groupId = Group.getByNameOrID(g['name']).id
        for perm in g['permission']:
            permId = Permission.getByNameOrID(perm).id
            r = GroupPermission(group_id=groupId, permission_id=permId)
            db.session.add(r)

    db.session.commit()


def populate():
    print("Creating initial user and permission...")
    try:
        createUsers()
        createGroups()
        createPermissions()
        addPermissionsGroup()
        addUserGroups()
    except sqlalchemy.exc.DBAPIError as e:
        print("Could not connect to the database.")
        print(e)
        exit(-1)

    # refresh views
    MVUserPermission.refresh()
    MVGroupPermission.refresh()
    db.session.commit()
    print("Success")


populate()
