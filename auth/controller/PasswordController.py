# This file contains function that implement password
# related policies

import binascii
from pbkdf2 import crypt
import os

from database.flaskAlchemyInit import HTTPRequestError
from database.historicModels import PasswdInactive


def create(passwd):
    # TODO: check password format policies
    salt = str(binascii.hexlify(os.urandom(8)), 'ascii')
    hash = crypt(passwd, salt, 1000).split('$').pop()
    return salt, hash


# update a passwd.
# verify if the new passwd was used before
# save the current passwd on inative table
def update(dbSession, user, newPasswd):
    # check actual passwd
    if user.hash == crypt(newPasswd, user.salt, 1000).split('$').pop():
        raise HTTPRequestError(400, "Please, choose a password"
                                    " not used before")

    # check all old password from database
    oldpwd = dbSession.query(PasswdInactive).filter_by(user_id=user.id).all()
    for pwd in oldpwd:
        if pwd.hash == crypt(newPasswd, pwd.salt, 1000).split('$').pop():
            raise HTTPRequestError(400, "Please, choose a password"
                                        " not used before")
    PasswdInactive.createInactiveFromUser(dbSession, user)
    return create(newPasswd)
