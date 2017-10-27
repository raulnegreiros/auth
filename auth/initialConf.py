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
        try:
            anotherUser = db.session.query(User.id) \
                                .filter_by(username=user['username']).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            print("That not the first container run. Skipping")
            exit(0)

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
        group = Group(**g)
        db.session.add(group)
    db.session.commit()


# A utility function to create a permission dict
# so the List 'predefPerms' get less verbose
def permissionDictHelper(id, path, method, permission=PermissionEnum.permit):
    return {
        "id": id,
        "path":  path,
        "method": method,
        "permission": permission
    }


def createPermissions():
    predefPerms = [
                    permissionDictHelper(1, "/template/(.*)", "(.*)"),
                    permissionDictHelper(2, "/template/(.*)", "GET"),
                    permissionDictHelper(3, "/device/(.*)", "(.*)"),
                    permissionDictHelper(4, "/device/(.*)", "GET"),
                    permissionDictHelper(5, "/flows/(.*)", "(.*)"),
                    permissionDictHelper(6, "/flows/(.*)", "GET"),
                    permissionDictHelper(7, "/history/(.*)", "(.*)"),
                    permissionDictHelper(8, "/history/(.*)", "GET"),
                    permissionDictHelper(9, "/metric/(.*)", "(.*)"),
                    permissionDictHelper(10, "/metric/(.*)", "GET"),
                    permissionDictHelper(11, "/mashup/(.*)", "(.*)"),
                    permissionDictHelper(12, "/mashup/(.*)", "GET"),
                    permissionDictHelper(13, "/auth/user/(.*)", "(.*)"),
                    permissionDictHelper(14, "/auth/user/(.*)", "GET"),
                    permissionDictHelper(15, "/pap/(.*)", "(.*)"),
                    permissionDictHelper(16, "/pap/(.*)", "GET")
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
            "permission": [1, 3, 5, 7, 9, 11, 13, 15]
        },
        {
            "name": "user",
            "permission": [1, 3, 5, 7, 9, 11]
        }
    ]

    for g in predefGroupPerm:
        groupId = Group.getByNameOrID(g['name']).id
        for permId in g['permission']:
            r = GroupPermission(group_id=groupId, permission_id=permId)
            db.session.add(r)

    db.session.commit()


def populate():
    print("Creating initial user and permission...")
    createUsers()
    createGroups()
    createPermissions()
    addPermissionsGroup()
    addUserGroups()

    # refresh views
    MVUserPermission.refresh()
    MVGroupPermission.refresh()
    db.session.commit()


populate()
