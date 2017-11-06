import sqlalchemy

from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError
import database.Cache as cache


def addUserGroup(dbSession, user, group):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        dbSession.query(UserGroup).filter_by(
                                                user_id=user.id,
                                                group_id=group.id
                                             ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        r = UserGroup(user_id=user.id, group_id=group.id)
        dbSession.add(r)
        cache.deleteKey(userid=user.id)
    else:
        raise HTTPRequestError(409, "User is already a member of the group")


def removeUserGroup(dbSession, user, group):
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
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "User is not a member of the group")


# add a user to a list of groups
def addUserManyGroups(dbSession, user, groups):
    success = []
    failed = []

    # if a single group was given. convert to a one element list
    if not isinstance(groups, list):
        groups = [groups]

    for g in groups:
        try:
            addUserGroup(dbSession, user, g)
            success.append(g)
        except HTTPRequestError:
            failed.append(g)
    return success, failed


def addGroupPermission(dbSession, group, permissionId):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        dbSession.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        r = GroupPermission(group_id=group.id, permission_id=permissionId)
        dbSession.add(r)
        cache.deleteKey(action=perm.method,
                        resource=perm.path)
    else:
        raise HTTPRequestError(409, "Group already have this permission")


def removeGroupPermission(dbSession, group, permissionId):
    try:
        group = Group.getByNameOrID(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID or name")
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = dbSession.query(GroupPermission) \
            .filter_by(group_id=group.id, permission_id=permissionId).one()
        dbSession.delete(relation)
        cache.deleteKey(action=perm.method,
                        resource=perm.path)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "Group does not have this permission")


def addUserPermission(dbSession, user, permissionId):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        dbSession.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        r = UserPermission(user_id=user.id, permission_id=permissionId)
        dbSession.add(r)
        cache.deleteKey(userid=user.id,
                        action=perm.method,
                        resource=perm.path)
    else:
        raise HTTPRequestError(409, "User already have this permission")


def removeUserPermission(dbSession, user, permissionId):
    try:
        user = User.getByNameOrID(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID or name")
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")
    try:
        relation = dbSession.query(UserPermission) \
            .filter_by(user_id=user.id, permission_id=permissionId).one()
        dbSession.delete(relation)
        cache.deleteKey(userid=user.id,
                        action=perm.method,
                        resource=perm.path)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "User does not have this permission")
