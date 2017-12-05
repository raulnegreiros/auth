# This file contains function to create, search, update and
# delete Users, groups and permissions
import sqlalchemy
import re

import controller.PasswordController as passwd
from database.Models import Permission, User, Group, PermissionEnum
from database.Models import UserPermission, GroupPermission, UserGroup
from database.flaskAlchemyInit import HTTPRequestError
from database.inputConf import UserLimits, PermissionLimits, GroupLimits
import database.Cache as cache
import database.historicModels as inactiveTables
import conf
from database.flaskAlchemyInit import log


# Helper function to check user fields
def checkUser(user, ignore=[]):
    if 'username' not in user.keys() or len(user['username']) == 0:
        raise HTTPRequestError(400, "Missing username")

    if len(user['username']) > UserLimits.username:
        raise HTTPRequestError(400, "Username too long")

    if re.match(r'^[a-z]+[a-z0-9_]', user['username']) is None:
        raise HTTPRequestError(400,
                               'Invalid username. usernames should start with'
                               ' a letter and only lowercase,'
                               ' alhpanumeric and underscores are allowed')

    if 'service' not in user.keys() or len(user['service']) == 0:
        raise HTTPRequestError(400, "Missing service")
    if len(user['service']) > UserLimits.service:
        raise HTTPRequestError(400, "Service too long")
    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise HTTPRequestError(400,
                               'Invalid username, only alhpanumeric'
                               ' and underscores allowed')

    if 'email' not in user.keys() or len(user['email']) == 0:
        raise HTTPRequestError(400, "Missing email")
    if len(user['email']) > UserLimits.email:
        raise HTTPRequestError(400, "E-mail too long")
    if re.match(
                r'(^[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$)',
                user['email']
                ) is None:
        raise HTTPRequestError(400, "Invalid email address")

    if 'name' not in user.keys() or len(user['name']) == 0:
        raise HTTPRequestError(400, "Missing user's name (full name)")
    if len(user['name']) > UserLimits.name:
        raise HTTPRequestError(400, "Name too long")

    if 'profile' not in user.keys() or len(user['profile']) == 0:
        raise HTTPRequestError(400, "Missing profile")
    if len(user['profile']) > UserLimits.profile:
        raise HTTPRequestError(400, "Profile name too long")

    return user


def createUser(dbSession, user, requester):
    # drop invalid fields
    user = {k: user[k] for k in user if k in User.fillable}
    checkUser(user)

    anotherUser = dbSession.query(User.id) \
                           .filter_by(username=user['username']).one_or_none()
    if anotherUser:
        raise HTTPRequestError(400, "username '"
                               + user['username']
                               + "' is in use.")

    anotherUser = dbSession.query(User.id) \
                           .filter_by(email=user['email']).one_or_none()
    if anotherUser:
        raise HTTPRequestError(400, "Email '" + user['email'] + "' is in use.")

    if conf.emailHost == 'NOEMAIL':
        user['salt'], user['hash'] = passwd.createPwd(conf.temporaryPassword)

    user['created_by'] = requester['userid']
    newUser = User(**user)
    log().info('user ' + user['username'] + ' created by '
               + requester['username'],
               newUser.safeDict())
    return newUser


def searchUser(dbSession, username=None):
    userQuery = dbSession.query(User)

    if (username is not None and len(username) > 0):
        userQuery = userQuery.filter(User.username.like('%' + username + '%'))

    users = userQuery.all()
    if not users:
        raise HTTPRequestError(404, "No results found with these filters")
    return users


def getUser(dbSession, user):
    try:
        user = User.getByNameOrID(user)
        return user
    except (sqlalchemy.orm.exc.NoResultFound, ValueError):
        raise HTTPRequestError(404, "No user found with this ID")


def updateUser(dbSession, user, updatedInfo, requester):
    # Drop invalid fields
    updatedInfo = {
                    k: updatedInfo[k]
                    for k in updatedInfo
                    if k in User.fillable
                  }
    oldUser = User.getByNameOrID(user)

    if 'username' in updatedInfo.keys() \
            and updatedInfo['username'] != oldUser.username:
        raise HTTPRequestError(400, "usernames can't be updated")

    checkUser(updatedInfo)

    # Verify if the email is in use by another user
    if 'email' in updatedInfo.keys() and updatedInfo['email'] != oldUser.email:
        anotherUser = dbSession.query(User) \
                               .filter_by(email=updatedInfo['email']) \
                               .one_or_none()
        if anotherUser:
            raise HTTPRequestError(400, "email already in use")

    log().info('user ' + oldUser.username + ' updated by '
               + requester['username'],
               {'oldUser': oldUser.safeDict(), 'newUser': updatedInfo})
    if 'name' in updatedInfo.keys():
        oldUser.name = updatedInfo['name']
    if 'service' in updatedInfo.keys():
        oldUser.service = updatedInfo['service']
    if 'email' in updatedInfo.keys():
        oldUser.email = updatedInfo['email']

    return oldUser


def deleteUser(dbSession, user, requester):
    try:
        user = User.getByNameOrID(user)
        if user.id == requester['userid']:
            raise HTTPRequestError(400, "a user can't remove himself")
        dbSession.execute(
            UserPermission.__table__.delete(UserPermission.user_id == user.id)
        )
        dbSession.execute(
            UserGroup.__table__.delete(UserGroup.user_id == user.id)
        )
        cache.deleteKey(userid=user.id)

        # The user is not hardDeleted.
        # it should be copied to inactiveUser table
        inactiveTables.PasswdInactive.createInactiveFromUser(dbSession,
                                                             user,)
        inactiveTables.UserInactive.createInactiveFromUser(dbSession,
                                                           user,
                                                           requester['userid'])
        passwd.expirePasswordResetRequests(dbSession, user.id)
        dbSession.delete(user)
        log().info('user ' + user.username + ' deleted by '
                   + requester['username'],
                   user.safeDict())
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No user found with this ID")


# Helper function to check permission fields
def checkPerm(perm):
    if 'name' not in perm.keys() or len(perm['name']) == 0:
        raise HTTPRequestError(400, "Missing permission name")
    if len(perm['path']) > PermissionLimits.path:
        raise HTTPRequestError(400, "Path too long")
    if re.match(r'^[a-z]+[a-z0-9_]', perm['name']) is None:
        raise HTTPRequestError(400,
                               'Invalid name. permission names should start'
                               ' with a letter and only lowercase,'
                               ' alhpanumeric and underscores are allowed')

    if 'permission' in perm.keys():
        if (perm['permission'] not in [p.value for p in PermissionEnum]):
            raise HTTPRequestError(400,
                                   "An access control rule can not return '"
                                   + perm['permission']
                                   + "'")
    else:
        # Default value if permission is omited
        perm['permission'] = 'permit'

    if 'path' not in perm.keys() or len(perm['path']) == 0:
        raise HTTPRequestError(400, "Missing permission Path")
    if len(perm['path']) > PermissionLimits.path:
        raise HTTPRequestError(400, "Path too long")

    if 'method' not in perm.keys() or len(perm['method']) == 0:
        raise HTTPRequestError(400, "Missing permission method")
    if len(perm['method']) > PermissionLimits.method:
        raise HTTPRequestError(400, "Method too long")

    try:
        re.match(r'(^' + perm['method'] + ')', "")
    except sre_constants.error:
        raise HTTPRequestError(perm['method']
                               + " is not a valid regular expression.")

    try:
        re.match(r'(^' + perm['path'] + ')', "")
    except sre_constants.error:
        raise HTTPRequestError(perm['method']
                               + " is not a valid regular expression.")


def createPerm(dbSession, permission, requester):
    permission = {
                    k: permission[k]
                    for k in permission
                    if k in Permission.fillable
                 }
    checkPerm(permission)
    permission['created_by'] = requester['userid']
    perm = Permission(**permission)
    log().info('permission ' + perm.name + ' deleted by '
               + requester['username'],
               perm.safeDict())
    return perm


def searchPerm(dbSession, path=None, method=None, permission=None):
    permQuery = dbSession.query(Permission)
    if (path is not None and len(path) > 0):
        permQuery = permQuery.filter(Permission.path.like('%' + path + '%'))
    if (method is not None and len(method) > 0):
        permQuery = permQuery.filter(
                    Permission.method.like('%' + method + '%'))
    if (permission is not None and len(permission) > 0):
        if (permission not in [p.value for p in PermissionEnum]):
            raise HTTPRequestError(400,
                                   "Invalid filter. Permission can't be '"
                                   + permission + "'")
        permQuery = permQuery.filter_by(permission=permission)

    perms = permQuery.all()
    if not perms:
        raise HTTPRequestError(404, "No results found with these filters")
    return perms


def getPerm(dbSession, permission):
    try:
        perm = Permission.getByNameOrID(permission)
        return perm
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")


def updatePerm(dbSession, permission, permData, requester):
    permData = {k: permData[k] for k in permData if k in Permission.fillable}
    checkPerm(permData)
    try:
        perm = Permission.getByNameOrID(permission)
        if 'name' in permData.keys() and perm.name != permData['name']:
            raise HTTPRequestError(400, "permission name can't be changed")
        for key, value in permData.items():
            setattr(perm, key, value)
        dbSession.add(perm)
        log().info('permission ' + perm.name + ' updated by '
                   + requester['username'],
                   permData)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID")


def deletePerm(dbSession, permission, requester):
    try:
        perm = Permission.getByNameOrID(permission)
        dbSession.execute(
            UserPermission.__table__
            .delete(UserPermission.permission_id == perm.id)
        )
        dbSession.execute(
            GroupPermission.__table__
            .delete(GroupPermission.permission_id == perm.id)
        )
        cache.deleteKey(action=perm.method, resource=perm.path)
        log().info('permission ' + str(perm.name) + ' deleted by '
                   + requester['username'],
                   perm.safeDict())
        dbSession.delete(perm)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No permission found with this ID or name")


def checkGroup(group):
    if 'name' not in group.keys() or len(group['name']) == 0:
        raise HTTPRequestError(400, 'Missing group name')
    if len(group['name']) > GroupLimits.name:
        raise HTTPRequestError(400, "Group name too long")

    if re.match(r'^[a-zA-Z0-9]+$', group['name']) is None:
        raise HTTPRequestError(400,
                               'Invalid group name, only alhpanumeric allowed')

    if 'desc' in group.keys() and len(group['desc']) > GroupLimits.description:
        raise HTTPRequestError(400, "Group description is too long")


def createGroup(dbSession, groupData, requester):
    groupData = {k: groupData[k] for k in groupData if k in Group.fillable}
    checkGroup(groupData)

    anotherGroup = dbSession.query(Group.id) \
                            .filter_by(name=groupData['name']).one_or_none()
    if anotherGroup:
        raise HTTPRequestError(400,
                               "Group name '"
                               + groupData['name'] + "' is in use.")

    groupData['created_by'] = requester['userid']
    g = Group(**groupData)
    log().info('group ' + g.name + ' created by '
               + requester['username'],
               g.safeDict())
    return g


def searchGroup(dbSession, name=None):
    groupQuery = dbSession.query(Group)
    if (name is not None and len(name) > 0):
        groupQuery = groupQuery.filter(Group.name.like('%' + name + '%'))

    groups = groupQuery.all()
    if not groups:
        raise HTTPRequestError(404, "No results found with these filters")

    return groups


def getGroup(dbSession, group):
    try:
        group = Group.getByNameOrID(group)
        return group
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")


def updateGroup(dbSession, group, groupData, requester):
    groupData = {k: groupData[k] for k in groupData if k in Group.fillable}
    checkGroup(groupData)
    try:
        group = Group.getByNameOrID(group)
        if 'name' in groupData.keys() and group.name != groupData['name']:
            raise HTTPRequestError(400, "groups name can't be changed")
        for key, value in groupData.items():
            setattr(group, key, value)
        dbSession.add(group)
        log().info('group ' + group.name + ' updated by '
                   + requester['username'],
                   groupData)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")


def deleteGroup(dbSession, group, requester):
    try:
        group = Group.getByNameOrID(group)
        dbSession.execute(
            GroupPermission.__table__
            .delete(GroupPermission.group_id == group.id)
        )
        dbSession.execute(
            UserGroup.__table__
            .delete(UserGroup.group_id == group.id)
        )
        cache.deleteKey()
        log().info('group ' + group.name + ' deleted by '
                   + requester['username'],
                   group.safeDict())
        dbSession.delete(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, "No group found with this ID")
