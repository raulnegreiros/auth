# this file contains function to check user credentials
# and generate a JWT token
import time
import binascii
import jwt
import sqlalchemy
from pbkdf2 import crypt
import os

from flaskAlchemyInit import HTTPRequestError
from database.Models import User
import conf

def authenticate(dbSession, username, passwd):
    try:
        user = dbSession.query(User).filter_by( username = username.lower() ).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(401,'not authorized')

    if user.hash == crypt(passwd, user.salt, 1000).split('$').pop():

        claims = {
            'iss': user.key,
            'iat': int(time.time()),
            'exp': int(time.time() + conf.tokenExpiration),
            'name': user.name,
            'email' : user.email,
            'profile' : 'admin',

            #generate a random string as nonce
            'jti' : str(binascii.hexlify(os.urandom(16)),'ascii'),
            'service': user.service,
            'username': user.username
        }
        encoded = jwt.encode(claims, user.secret, algorithm='HS256')
        return str(encoded,'ascii')

    raise HTTPRequestError(401,'not authorized')
