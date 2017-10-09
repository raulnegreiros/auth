#this file contains function to create search, update and
# delete Users, groups and permissions
import sqlalchemy
import re
import os
import binascii
from pbkdf2 import crypt

from database.Models import Permission, User, Group, PermissionEnum
from flaskAlchemyInit import HTTPRequestError

#helper function to check user fields
def checkUser(user, ignore = []):
    if 'username' not in user.keys() or len(user['username']) == 0:
        raise HTTPRequestError(400,'Missing username')

    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise HTTPRequestError(400,'Invalid username, only lowercase alhpanumeric and underscores allowed')

    if ('passwd' not in ignore) and ('passwd' not in user.keys() or len(user['passwd']) == 0):
        raise HTTPRequestError(400,'Missing passwd')

    if 'service' not in user.keys() or len(user['service']) == 0:
        raise HTTPRequestError(400,'Missing service')
    if re.match(r'^[a-z0-9_]+$', user['username']) is None:
        raise HTTPRequestError(400,'Invalid username, only alhpanumeric and underscores allowed')

    if 'email' not in user.keys() or len(user['email']) == 0:
        raise HTTPRequestError(400,'Missing email')
    if re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', user['email']) is None:
        raise HTTPRequestError(400,'Invalid email address')

    if 'name' not in user.keys() or len(user['name']) == 0:
        raise HTTPRequestError(400,"Missing user's name (full name)")

    return user

#user CRUD
def createUser(dbSession, user):
    # drop invalid fields
    user = {k: user[k] for k in user if k in User.fillable + ['passwd']}
    checkUser(user)

    try:
        anotherUser =  dbSession.query(User.id).filter_by(username=user['username']).one()
        raise HTTPRequestError(400,"username '" + user['username'] + "' is in use.")
    except sqlalchemy.orm.exc.NoResultFound:
        pass

    try:
        anotherUser =  dbSession.query(User.id).filter_by(email=user['email']).one()
        raise HTTPRequestError(400,"Email '" + user['email'] + "' is in use.")
    except sqlalchemy.orm.exc.NoResultFound:
        pass
    user['salt'] = str(binascii.hexlify(os.urandom(8)),'ascii')
    user['hash'] = crypt(user['passwd'], user['salt'], 1000).split('$').pop()
    del user['passwd']

    user = User(**user)
    return user

def searchUser(dbSession, username = None):
    userQuery = dbSession.query(User)

    if (username is not None and len(username) > 0):
        userQuery = userQuery.filter(User.username.like('%' + username + '%'))

    users = userQuery.all()
    if (len(users) == 0):
        raise HTTPRequestError(404,"No results found with these filters")
    return users

def getUser(dbSession, userId: int):
    try:
        user = dbSession.query(User).filter_by( id = userId ).one()
        return user
    except (sqlalchemy.orm.exc.NoResultFound, ValueError):
        raise HTTPRequestError(404,"No user found with this ID")

def updateUser(dbSession, userId: int, updatedInfo):
    #drop invalid fields
    updatedInfo = {k: updatedInfo[k] for k in updatedInfo if k in User.fillable + ['passwd']}
    oldUser = getUser(dbSession, userId)

    if 'username' in updatedInfo.keys() and updatedInfo['username'] != oldUser.username:
        raise HTTPRequestError(400,"usernames can't be updated")

    if 'passwd' not in updatedInfo.keys():
        checkUser(updatedInfo, ['passwd'])
    else:
        checkUser(updatedInfo)

    #verify if the email is in use by another user
    if 'email' in updatedInfo.keys() and updatedInfo['email'] != oldUser.email:
        try:
            anotherUser = dbSession.query(User).filter_by( email = updatedInfo['email'] ).one()
            raise HTTPRequestError(400,'email already in use')
        except sqlalchemy.orm.exc.NoResultFound:
            pass

    if 'passwd' in updatedInfo.keys():
        oldUser.salt = str(binascii.hexlify(os.urandom(8)),'ascii')
        oldUser.hash = crypt(updatedInfo['passwd'], oldUser.salt, 1000).split('$').pop()
        del updatedInfo['passwd']

    #TODO: find a iterative way
    if 'name' in updatedInfo.keys() : oldUser.name =  updatedInfo['name']
    if 'service' in updatedInfo.keys() : oldUser.service =  updatedInfo['service']
    if 'email' in updatedInfo.keys() : oldUser.email =  updatedInfo['email']

    return oldUser

def deleteUser(dbSession, userId: int):
    try:
        user = dbSession.query(User).filter_by(id = userId).one()
        dbSession.delete(user)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404,"No user found with this ID")

#helper function to check permission fields
def checkPerm(perm):
    if 'permission' in perm.keys():
        if (perm['permission'] not in [p.value for p in PermissionEnum]):
            raise HTTPRequestError(400,"An access control rule can not return '" + perm['permission'] + "'")
    else:
        #default value
        perm['permission'] = 'permit'

    if 'path' not in perm.keys() or len(perm['path']) == 0:
        raise HTTPRequestError(400,'Missing permission Path')

    if 'method' not in perm.keys() or len(perm['method']) == 0:
        raise HTTPRequestError(400,'Missing permission method')
    #TODO: check if path and method are valid regex

#creae a permission
def createPerm(dbSession, permission):
    permission = {k: permission[k] for k in permission if k in Permission.fillable}
    checkPerm(permission)
    perm = Permission(**permission)
    return perm

def searchPerm(dbSession, path=None, method=None, permission=None):
    permQuery = dbSession.query(Permission)
    if (path is not None and len(path) > 0):
        permQuery = permQuery.filter(Permission.path.like('%' + path + '%'))
    if (method is not None and len(method) > 0):
        permQuery = permQuery.filter(Permission.method.like('%' + method + '%'))
    if (permission is not None and len(permission) > 0):
        if (permission not in [p.value for p in PermissionEnum]):
            raise HTTPRequestError(400,"Invalid filter. Permission can't be '" + permission + "'")
        permQuery = permQuery.filter_by(permission=permission)

    perms = permQuery.all()
    if (len(perms) == 0):
        raise HTTPRequestError(404,"No results found with these filters")
    return perms

def getPerm(dbSession, permissionId: int):
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
        return perm
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404,"No permission found with this ID")

def updatePerm(dbSession, permissionId: int, permData):
    permData = {k: permData[k] for k in permData if k in Permission.fillable}
    checkPerm(permData)
    updated = dbSession.query(Permission).filter_by(id=permissionId) \
            .update(permData)
    if (updated == 0):
        raise HTTPRequestError(404,"No permission found with this ID")

def deletePerm(dbSession, permissionId):
    try:
        perm = dbSession.query(Permission).filter_by(id=permissionId).one()
        dbSession.delete(perm)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404,"No permission found with this ID")

def checkGroup(group):
    if 'name' not in group.keys() or len(group['name']) == 0:
        raise HTTPRequestError(400,'Missing group name')
    if re.match(r'^[a-zA-Z0-9]+$', group['name']) is None:
        raise HTTPRequestError(400,'Invalid group name, only alhpanumeric allowed')

    #TODO: must chekc the description?

def createGroup(dbSession, groupData):
    groupData = {k: groupData[k] for k in groupData if k in Group.fillable}
    checkGroup(groupData)
    try:
        anotherGroup =  dbSession.query(Group.id).filter_by(name=groupData['name']).one()
        raise HTTPRequestError(400,"Group name '" + groupData['name'] + "' is in use.")
    except sqlalchemy.orm.exc.NoResultFound:
        pass
    g = Group(**groupData)
    return g

def searchGroup(dbSession, name=None):
    groupQuery = dbSession.query(Group)
    if (name is not None and len(name) > 0):
        groupQuery = groupQuery.filter(Group.name.like('%' + name + '%'))

    groups = groupQuery.all()
    if (len(groups) == 0):
        raise HTTPRequestError(404,"No results found with these filters")

    return groups

def getGroup(dbSession, groupId: int):
    try:
        group = dbSession.query(Group).filter_by(id=groupId).one()
        return group
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404,"No group found with this ID")

def updateGroup(dbSession, groupId : int, groupData):
    groupData = {k: groupData[k] for k in groupData if k in Group.fillable}
    checkGroup(groupData)
    updated = dbSession.query(Group).filter_by(id=groupId) \
            .update(groupData)
    if (updated == 0):
        raise HTTPRequestError(404,"No group found with this ID")

def deleteGroup(dbSession, groupId : int):
    try:
        group = dbSession.query(Group).filter_by(id=groupId).one()
        dbSession.delete(group)
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404,"No group found with this ID")
