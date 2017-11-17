import sqlalchemy

from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError
import database.Cache as cache
from database.flaskAlchemyInit import log


def addUserGroup(dbSession, user, group, requester):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")

    if dbSession.query(UserGroup).filter_by(
                                                user_id=user.id,
                                                group_id=group.id
                                             ).one_or_none():
        raise HTTPRequestError(409, "User is already a member of the group")

    r = UserGroup(user_id=user.id, group_id=group.id)
    dbSession.add(r)
    cache.deleteKey(userid=user.id)
    log().info('user ' + user.username + ' added to group ' + group.name
               + ' by ' + requester['username'])


def removeUserGroup(dbSession, user, group, requester):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        relation = dbSession.query(UserGroup) \
            .filter_by(user_id=user.id, group_id=group.id).one()
        dbSession.delete(relation)
        cache.deleteKey(userid=user.id)
        log().info('user ' + user.username + ' removed from ' + group.name
                   + ' by ' + requester['username'])
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "User is not a member of the group")


# add a user to a list of groups
def addUserManyGroups(dbSession, user, groups, requester):
    success = []
    failed = []

    # if a single group was given. convert to a one element list
    if not isinstance(groups, list):
        groups = [groups]

    for g in groups:
        try:
            addUserGroup(dbSession, user, g, requester)
            success.append(g)
        except HTTPRequestError:
            failed.append(g)
    return success, failed


def addGroupPermission(dbSession, group, permission, requester):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID or name")

    if dbSession.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=perm.id).one_or_none():
        raise HTTPRequestError(409, "Group already have this permission")

    r = GroupPermission(group_id=group.id, permission_id=perm.id)
    dbSession.add(r)
    cache.deleteKey(action=perm.method,
                    resource=perm.path)
    log().info('permission ' + perm.name + ' added to group ' + group.name
               + ' by ' + requester['username'])


def removeGroupPermission(dbSession, group, permission, requester):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = dbSession.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=perm.id).one()
        dbSession.delete(relation)
        cache.deleteKey(action=perm.method,
                        resource=perm.path)
        log().info('permission ' + perm.name + ' removed from '
                   ' group ' + group.name + ' by ' + requester['username'])
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "Group does not have this permission")


def addUserPermission(dbSession, user, permission, requester):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")

    if dbSession.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=perm.id).one_or_none():
        raise HTTPRequestError(409, "User already have this permission")

    r = UserPermission(user_id=user.id, permission_id=perm.id)
    dbSession.add(r)
    cache.deleteKey(userid=user.id,
                    action=perm.method,
                    resource=perm.path)
    log().info('user ' + user.username + ' received permission '
               + perm.name + ' by ' + requester['username'])


def removeUserPermission(dbSession, user, permission, requester):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = Permission.getByNameOrID(permission)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = dbSession.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=perm.id).one()
        dbSession.delete(relation)
        cache.deleteKey(userid=user.id,
                        action=perm.method,
                        resource=perm.path)
        log().info('user ' + user.username + ' removed permission '
                   + perm.name + ' by ' + requester['username'])
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "User does not have this permission")
