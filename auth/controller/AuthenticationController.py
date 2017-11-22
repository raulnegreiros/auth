# this file contains function to check user credentials
# and generate a JWT token
import time
import binascii
import jwt
import sqlalchemy
from pbkdf2 import crypt
import os

from database.flaskAlchemyInit import HTTPRequestError
from database.Models import User
import conf
from database.flaskAlchemyInit import log
import sqlalchemy


def authenticate(dbSession, authData):
    if 'username' not in authData.keys():
        raise HTTPRequestError(400, 'missing username')
    if 'passwd' not in authData.keys():
        raise HTTPRequestError(400, 'missing passwd')

    username = authData['username']
    passwd = authData['passwd']

    try:
        user = dbSession.query(User).filter_by(username=username.lower()).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(401, 'not authorized')
    except sqlalchemy.exc.DBAPIError:
        raise HTTPRequestError(500, 'Problem connecting to database')

    if not user.hash:
        raise HTTPRequestError(401, 'This user is inactive')

    if user.hash == crypt(passwd, user.salt, 1000).split('$').pop():
        groupsId = [g.id for g in user.groups]

        claims = {
            'iss': user.key,
            'iat': int(time.time()),
            'exp': int(time.time() + conf.tokenExpiration),
            'name': user.name,
            'email': user.email,
            'profile': user.profile,  # Obsolete. Kept for compatibility
            'groups': groupsId,
            'userid': user.id,

            # Generate a random string as nonce
            'jti': str(binascii.hexlify(os.urandom(16)), 'ascii'),
            'service': user.service,
            'username': user.username
        }
        encoded = jwt.encode(claims, user.secret, algorithm='HS256')
        log().info('user ' + user.username + ' loged in')
        return str(encoded, 'ascii')

    raise HTTPRequestError(401, 'not authorized')


# this helper function receive a base64 JWT token
# the function decodes the JWT, check the signature (if configured to check)
# and returns the jwt payload as a python dictionary
def getJwtPayload(rawJWT):
    if not rawJWT:
        raise HTTPRequestError(401, "not authorized")

    # remove the bearer of the token
    splittedToken = rawJWT.split(' ')
    if len(splittedToken) > 1:
        rawJWT = splittedToken[1]

    try:
        jwtPayload = jwt.decode(rawJWT, verify=False)
    except jwt.exceptions.DecodeError:
        raise HTTPRequestError(401, "Corrupted JWT")

    try:
        user_id = jwtPayload['userid']
    except KeyError:
        raise HTTPRequestError(401, "Invalid JWT payload")

    # now that we know the user, we know the secret
    # and can check the jwt signature
    if conf.checkJWTSign:
        try:
            user = dbSession.query(User). \
                    filter_by(user_id=jwtPayload['userid']).one()
            options = {
                'verify_exp': False,
            }
            jwt.decode(rawJWT,
                       user.secret, algorithm='HS256', options=options)
        except (jwt.exceptions.DecodeError, sqlalchemy.orm.exc.NoResultFound):
            raise HTTPRequestError(401, "Invalid JWT signaure")
        except sqlalchemy.exc.DBAPIError:
            raise HTTPRequestError(500, 'Problem connecting to database')
    return jwtPayload


def userIdFromJWT(token):
    if not token:
        raise HTTPRequestError(401, "not authorized")
    return getJwtPayload(token)['userid']
