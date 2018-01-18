# this file contains useful functions for
# getting information about permissions, groups and users
import sqlalchemy.orm.exc as orm_exceptions

from database.Models import User, Group
from database.flaskAlchemyInit import HTTPRequestError


def get_user_direct_permissions(db_session, user):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")
    return user.permissions


def get_all_user_permissions(db_session, user):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")

    permissions = user.permissions
    permissions += [perm
                    for group in user.groups
                    for perm in group.permissions]

    # drop possible duplicates
    return list({v.id: v for v in permissions}.values())


def get_user_groups(db_session, user):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this username or ID")
    else:
        return user.groups


def get_group_permissions(db_session, group):
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this name or ID")
    else:
        return group.permissions


def get_group_users(db_session, group):
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this name or ID")
    else:
        return group.users
