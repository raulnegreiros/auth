#!/usr/bin/python3
# This script creates the initial groups, permissions and users

import binascii
import os
from pbkdf2 import crypt
from sqlalchemy import exc as sqlalchemy_exceptions
from database.flaskAlchemyInit import db
from database.Models import PermissionEnum, User, PermissionTypeEnum, Permission, MVUserPermission, MVGroupPermission, \
    Group, GroupPermission, UserGroup
import kongUtils as kong


def create_users():
    predef_users = [
        {
            "name": "testadm",
            "username": "testadm",
            "service": "admin",
            "email": "testadm@noemail.com",
            "profile": "testadm",
            "passwd": "admin"
        }
    ]

    for user in predef_users:
        # check if the user already exists
        # if the user exist, chances are this scrip has been run before
        print("Querying database for user {}".format(user))
        another_user = db.session.query(User.id) \
            .filter_by(username=user['username']) \
            .one_or_none()
        if another_user:
            print("This is not the first container run. Skipping")
            exit(0)
        print("Database access returned.")

        # mark the user as automatically created
        user['created_by'] = 0

        # hash the password
        user['salt'] = str(binascii.hexlify(os.urandom(8)), 'ascii')
        user['hash'] = crypt(user['passwd'],
                             user['salt'],
                             1000).split('$').pop()
        del user['passwd']
        print("Creating a new instance of this user.")
        new_user = User(**user)
        print("New instance created.")

        # configure kong shared secret
        kong_data = kong.configure_kong(new_user.username)
        if kong_data is None:
            print('failed to configure verification subsystem')
            exit(-1)
        new_user.secret = kong_data['secret']
        new_user.key = kong_data['key']
        new_user.kongId = kong_data['kongid']
        db.session.add(new_user)
    db.session.commit()


def create_groups():
    predef_groups = [
        {
            "name": "testadm",
            "description": "Group with the highest access privilege"
        },
        {
            "name": "testuser",
            "description": "This groups can do anything, except manage users"
        }
    ]
    for g in predef_groups:
        # mark the group as automatically created
        g['created_by'] = 0
        group = Group(**g)
        db.session.add(group)
    db.session.commit()


# A utility function to create a permission dict
# so the List 'predefPerms' get less verbose
def permission_dict_helper(name, path, method, permission=PermissionEnum.permit, type_perm=PermissionTypeEnum.system):
    return {
        "name": name,
        "path": path,
        "method": method,
        "permission": permission,
        "type": type_perm,
        "created_by": 0
    }


def add_user_groups():
    predef_user_group = [
        {
            "name": "testadm",
            "groups": ["testadm"]
        },
    ]

    for user in predef_user_group:
        user_id = User.get_by_name_or_id(user['name']).id
        for group_name in user['groups']:
            r = UserGroup(user_id=user_id,
                          group_id=Group.get_by_name_or_id(group_name).id)
            db.session.add(r)
    db.session.commit()


def add_permissions_group():
    predef_group_perm = [
        {
            "name": "testadm",
            "permission": [
                'all_all'
            ]
        },
        {
            "name": "testuser",
            "permission": [
                'all_template',
                'all_device',
                'all_flows',
                'ro_history',
                'ro_ca',
                'wo_sign',
                "ro_socketio",
                "all_import",
                "ro_export",
                "ro_mqqt_metrics",
                "all_image"
            ]
        }
    ]

    for group in predef_group_perm:
        group_id = Group.get_by_name_or_id(group['name']).id
        for perm in group['permission']:
            perm_id = Permission.get_by_name_or_id(perm).id
            r = GroupPermission(group_id=group_id, permission_id=perm_id)
            db.session.add(r)

    db.session.commit()


def populate():
    print("Creating initial user and permission for test...")
    try:
        create_users()
        create_groups()
        add_permissions_group()
        add_user_groups()
    except sqlalchemy_exceptions.DBAPIError as err:
        print("Could not connect to the database.")
        print(err)
        exit(-1)

    # refresh views
    MVUserPermission.refresh()
    MVGroupPermission.refresh()
    db.session.commit()
    print("Success")


populate()
