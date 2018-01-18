#!/usr/bin/python3
# This script creates the initial groups, permissions and users

import binascii
import os
from pbkdf2 import crypt

from sqlalchemy import exc as sqlalchemy_exceptions

from database.flaskAlchemyInit import db
from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.Models import MVUserPermission, MVGroupPermission

import kongUtils as kong


def create_users():
    predef_users = [
        {
            "name": "Admin (superuser)",
            "username": "admin",
            "service": "admin",
            "email": "admin@noemail.com",
            "profile": "admin",
            "passwd": "admin"
        }
    ]

    for user in predef_users:
        # check if the user already exists
        # if the user exist, chances are this scrip has been run before
        another_user = db.session.query(User.id) \
                                .filter_by(username=user['username']) \
                                .one_or_none()
        if another_user:
            print("This is not the first container run. Skipping")
            exit(0)
        # mark the user as automatically created
        user['created_by'] = 0

        # hash the password
        user['salt'] = str(binascii.hexlify(os.urandom(8)), 'ascii')
        user['hash'] = crypt(user['passwd'],
                             user['salt'],
                             1000).split('$').pop()
        del user['passwd']
        new_user = User(**user)

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
            "name": "admin",
            "description": "Group with the highest access privilege"
        },
        {
            "name": "user",
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
def permission_dict_helper(name, path, method, permission=PermissionEnum.permit):
    return {
        "name": name,
        "path":  path,
        "method": method,
        "permission": permission,
        "created_by": 0
    }


def create_permissions():
    predef_perms = [
        permission_dict_helper('all_all', "/(.*)", "(.*)"),
        permission_dict_helper('all_template', "/template/(.*)", "(.*)"),
        permission_dict_helper('ro_template', "/template/(.*)", "GET"),
        permission_dict_helper('all_device', "/device/(.*)", "(.*)"),
        permission_dict_helper('ro_device', "/device/(.*)", "GET"),
        permission_dict_helper('all_flows', "/flows/(.*)", "(.*)"),
        permission_dict_helper('ro_flows', "/flows/(.*)", "GET"),
        permission_dict_helper('all_history', "/history/(.*)", "(.*)"),
        permission_dict_helper('ro_history', "/history/(.*)", "GET"),
        permission_dict_helper('all_metric', "/metric/(.*)", "(.*)"),
        permission_dict_helper('ro_metric', "/metric/(.*)", "GET"),
        permission_dict_helper('all_mashup', "/mashup/(.*)", "(.*)"),
        permission_dict_helper('ro_mashup', "/mashup/(.*)", "GET"),
        permission_dict_helper('all_user', "/auth/user/(.*)", "(.*)"),
        permission_dict_helper('ro_user', "/auth/user/(.*)", "GET"),
        permission_dict_helper('all_pap', "/pap/(.*)", "(.*)"),
        permission_dict_helper('ro_pap', "/pap/(.*)", "GET"),
        permission_dict_helper('ro_ca', "/ca/(.*)", "GET"),
        permission_dict_helper('wo_sign', "/sign/(.*)", "POST"),
        permission_dict_helper('ro_alarms', "/alarmmanager/(.*)", "GET")
    ]

    for p in predef_perms:
        perm = Permission(**p)
        db.session.add(perm)
    db.session.commit()


def add_user_groups():
    predef_user_group = [
        {
            "name": "admin",
            "groups": ["admin"]
        },
    ]

    for user in predef_user_group:
        user_id = User.getByNameOrID(user['name']).id
        for group_name in user['groups']:
            r = UserGroup(user_id=user_id,
                          group_id=Group.getByNameOrID(group_name).id)
            db.session.add(r)
    db.session.commit()


def add_permissions_group():
    predef_group_perm = [
        {
            "name": "admin",
            "permission": [
                'all_all'
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
                'ro_alarms',
                'ro_ca',
                'wo_sign'
            ]
        }
    ]

    for group in predef_group_perm:
        group_id = Group.getByNameOrID(group['name']).id
        for perm in group['permission']:
            perm_id = Permission.getByNameOrID(perm).id
            r = GroupPermission(group_id=group_id, permission_id=perm_id)
            db.session.add(r)

    db.session.commit()


def populate():
    print("Creating initial user and permission...")
    try:
        create_users()
        create_groups()
        create_permissions()
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
