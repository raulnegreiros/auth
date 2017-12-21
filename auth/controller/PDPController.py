import re
import sqlalchemy

import conf
from database.Models import Permission, User, Group, PermissionEnum
from database.Models import MVUserPermission, MVGroupPermission
from database.flaskAlchemyInit import HTTPRequestError, app
from controller.AuthenticationController import getJwtPayload
import database.Cache as cache
from database.flaskAlchemyInit import log


# Helper function to check request fields
def checkRequest(pdpRequest):
    if 'action' not in pdpRequest.keys() or len(pdpRequest['action']) == 0:
        raise HTTPRequestError(400, "Missing action")

    if 'jwt' not in pdpRequest.keys() or len(pdpRequest['jwt']) == 0:
        raise HTTPRequestError(400, "Missing JWT")

    if 'resource' not in pdpRequest.keys() or len(pdpRequest['resource']) == 0:
        raise HTTPRequestError(400, "Missing resource")


def pdpMain(dbSession, pdpRequest):
    checkRequest(pdpRequest)
    jwtPayload = getJwtPayload(pdpRequest['jwt'])
    user_id = jwtPayload['userid']

    # try to retrieve the veredict from cache
    cachedVeredict = cache.getKey(user_id, pdpRequest['action'],
                                  pdpRequest['resource'])
    # Return the cached answer if it exist
    if cachedVeredict:
        log().info('user ' + str(user_id) + ' '
                   + cachedVeredict + ' to ' + pdpRequest['action']
                   + ' on ' + pdpRequest['resource'])
        return cachedVeredict

    veredict = iteratePermissions(user_id,
                                  jwtPayload['groups'],
                                  pdpRequest['action'],
                                  pdpRequest['resource'])
    # Registry this veredict on cache
    cache.setKey(user_id,
                 pdpRequest['action'],
                 pdpRequest['resource'],
                 veredict)

    log().info('user ' + str(user_id) + ' '
             + veredict + ' to ' + pdpRequest['action']
             + ' on ' + pdpRequest['resource'])
    return veredict


def iteratePermissions(user_id, groupsList, action, resource):
    permit = False

    # check user direct permissions
    for p in MVUserPermission.query.filter_by(user_id=user_id):
        granted = makeDecision(p, action, resource)
        # user permissions have precedence over group permissions
        if granted != PermissionEnum.notApplicable:
            return granted.value

    # check user group permissions
    for g in groupsList:
        for p in MVGroupPermission.query.filter_by(group_id=g):
            granted = makeDecision(p, action, resource)
            # deny have precedence over permits
            if granted == PermissionEnum.deny:
                return granted.value
            elif granted == PermissionEnum.permit:
                permit = True

    if permit:
        return PermissionEnum.permit.value
    else:
        return PermissionEnum.deny.value


# Receive a Permissions and try to match the Given
# path + method with it. Return 'permit' or 'deny' if succed matching.
# return 'notApplicable' otherwise
def makeDecision(permission, method, path):
    # if the Path and method Match
    if re.match(r'(^' + permission.path + ')', path) is not None:
        if re.match(r'(^' + permission.method + ')', method):
            return permission.permission
    return PermissionEnum.notApplicable
