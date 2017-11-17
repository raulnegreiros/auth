# this file contains usefull functions for
# easily get information about permissions, groups and user
import sqlalchemy

from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError


def getUserDirectPermissions(dbSession, user):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")

    return user.permissions


def getAllUserPermissions(dbSession, user):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")

    permissions = user.permissions
    permissions += [perm
                    for group in user.groups
                    for perm in group.permissions]

    # drop possible duplicates
    return list({v.id: v for v in permissions}.values())


def getUserGrups(dbSession, user):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")
    else:
        return user.groups


def getGroupPermissions(dbSession, group):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this name or ID")
    else:
        return group.permissions


def getGroupUsers(dbSession, group):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this name or ID")
    else:
        return group.users
