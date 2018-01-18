import sqlalchemy.orm.exc as orm_exceptions

from database.Models import Permission, User, Group
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError
import database.Cache as cache
from database.flaskAlchemyInit import log


def add_user_group(db_session, user, group, requester):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")

    if db_session.query(UserGroup).filter_by(
                                                user_id=user.id,
                                                group_id=group.id
                                             ).one_or_none():
        raise HTTPRequestError(409, "User is already a member of the group")

    r = UserGroup(user_id=user.id, group_id=group.id)
    db_session.add(r)
    cache.delete_key(userid=user.id)
    log().info('user ' + user.username + ' added to group ' + group.name
               + ' by ' + requester['username'])


def remove_user_group(db_session, user, group, requester):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        relation = db_session.query(UserGroup) \
            .filter_by(user_id=user.id, group_id=group.id).one()
        db_session.delete(relation)
        cache.delete_key(userid=user.id)
        log().info('user ' + user.username + ' removed from ' + group.name
                   + ' by ' + requester['username'])
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "User is not a member of the group")


# add a user to a list of groups
def add_user_many_groups(db_session, user, groups, requester):
    success = []
    failed = []

    # if a single group was given. convert to a one element list
    if not isinstance(groups, list):
        groups = [groups]

    for g in groups:
        try:
            add_user_group(db_session, user, g, requester)
            success.append(g)
        except HTTPRequestError:
            failed.append(g)
    return success, failed


def add_group_permission(db_session, group, permission, requester):
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID or name")

    if db_session.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=perm.id).one_or_none():
        raise HTTPRequestError(409, "Group already have this permission")

    r = GroupPermission(group_id=group.id, permission_id=perm.id)
    db_session.add(r)
    cache.delete_key(action=perm.method,
                     resource=perm.path)
    log().info('permission ' + perm.name + ' added to group ' + group.name
               + ' by ' + requester['username'])


def remove_group_permission(db_session, group, permission, requester):
    try:
        group = Group.getByNameOrID(group)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = db_session.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=perm.id).one()
        db_session.delete(relation)
        cache.delete_key(action=perm.method,
                         resource=perm.path)
        log().info('permission ' + perm.name + ' removed from '
                   ' group ' + group.name + ' by ' + requester['username'])
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "Group does not have this permission")


def add_user_permission(db_session, user, permission, requester):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")

    if db_session.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=perm.id).one_or_none():
        raise HTTPRequestError(409, "User already have this permission")

    r = UserPermission(user_id=user.id, permission_id=perm.id)
    db_session.add(r)
    cache.delete_key(userid=user.id,
                     action=perm.method,
                     resource=perm.path)
    log().info('user ' + user.username + ' received permission '
               + perm.name + ' by ' + requester['username'])


def remove_user_permission(db_session, user, permission, requester):
    try:
        user = User.getByNameOrID(user)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = db_session.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=perm.id).one()
        db_session.delete(relation)
        cache.delete_key(userid=user.id,
                         action=perm.method,
                         resource=perm.path)
        log().info('user ' + user.username + ' removed permission '
                   + perm.name + ' by ' + requester['username'])
    except orm_exceptions.NoResultFound:
        raise HTTPRequestError(404, "User does not have this permission")
