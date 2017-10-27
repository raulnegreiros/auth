import re
import jwt
import sqlalchemy

from database.Models import Permission, User, Group, PermissionEnum
from database.Models import MVUserPermission, MVGroupPermission
from database.flaskAlchemyInit import HTTPRequestError
import conf


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
    try:
        jwtPayload = jwt.decode(pdpRequest['jwt'], verify=False)
    except jwt.exceptions.DecodeError:
        raise HTTPRequestError(400, "Corrupted JWT")

    # TODO: Create a materialised view (or two)

    try:
        user = dbSession.query(User). \
                filter_by(username=jwtPayload['username']).one()
    except (sqlalchemy.orm.exc.NoResultFound, KeyError):
        raise HTTPRequestError(400, "Invalid JWT payload")

    # now that we know the user, we know the secret
    # and can check the jwt signature
    if conf.kongURL != 'DISABLED':
        try:
            options = {
                'verify_exp': False,
            }
            jwt.decode(pdpRequest['jwt'],
                       user.secret, algorithm='HS256', options=options)
        except jwt.exceptions.DecodeError:
            raise HTTPRequestError(400, "Invalid JWT signaure")

    # check user direct permissions
    for p in MVUserPermission.query.filter_by(user_id=user.id):
        granted = makeDecision(p, pdpRequest['action'], pdpRequest['resource'])
        if granted != PermissionEnum.notApplicable:
            return granted.value

    # chekc user group permissions
    for g in jwtPayload['groups']:
        for p in MVGroupPermission.query.filter_by(group_id=g):
            granted = makeDecision(p,
                                   pdpRequest['action'],
                                   pdpRequest['resource'])
            if granted != PermissionEnum.notApplicable:
                return granted.value

    return PermissionEnum.deny.value


# Receive a permissions and try to match the Given
# path + method with it. Return 'permit' or 'deny' if succed matching.
# return 'notApplicable' otherwise
def makeDecision(permission, method, path):
    # if the Path and method Match
    if re.match(r'(^' + permission.path + ')', path) is not None:
        if re.match(r'(^' + permission.method + ')', method):
            return permission.permission
    return PermissionEnum.notApplicable
