# This file contains function that implement password
# related policies

import binascii
from pbkdf2 import crypt
import os
import sqlalchemy
import datetime

from database.flaskAlchemyInit import HTTPRequestError
from database.historicModels import PasswdInactive, PasswordRequestInactive
from database.Models import PasswordRequest, User
from utils.emailUtils import sendMail
import conf


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
    if user.hash and (user.hash ==
                      crypt(newPasswd, user.salt, 1000).split('$').pop()):
        raise HTTPRequestError(400, "Please, choose a password"
                                    " not used before")

    # check all old password from database
    if conf.passwdHistoryLen > 0:
        oldpwds = (
                    dbSession.query(PasswdInactive)
                    .filter_by(user_id=user.id)
                    .order_by(PasswdInactive.deletion_date.desc())
                    .limit(conf.passwdHistoryLen)
                   )

        for pwd in oldpwds:
            if pwd.hash == crypt(newPasswd, pwd.salt, 1000).split('$').pop():
                raise HTTPRequestError(400, "Please, choose a password"
                                            " not used before")
    PasswdInactive.createInactiveFromUser(dbSession, user)
    return create(newPasswd)


# an authenticated user can update it password
def updateEndpoint(dbSession, userId, upData):
    if 'oldpasswd' not in upData.keys() or len(upData['oldpasswd']) == 0:
        raise HTTPRequestError(400, "Missing user's oldpasswd")

    if 'newpasswd' not in upData.keys() or len(upData['newpasswd']) == 0:
        raise HTTPRequestError(400, "Missing user's newpasswd")

    try:
        user = dbSession.query(User). \
            filter_by(id=userId).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, 'User not found')

    if user.hash and (user.hash ==
       crypt(upData['oldpasswd'], user.salt, 1000).split('$').pop()):
        user.salt, user.hash = update(dbSession, user, upData['newpasswd'])
        dbSession.add(user)
    else:
        raise HTTPRequestError(400, "Incorrect password")


# chech if a PasswordRequest expired
# if it is, will be removed
def chechRequestValidity(dbSession, resetRequest):
    if ((resetRequest.created_date
        + datetime.timedelta(minutes=conf.passwdRequestExpiration))
            < datetime.datetime.utcnow()):
        # save on inactive table before deletion
        PasswordRequestInactive.createInactiveFromRequest(dbSession,
                                                          resetRequest)
        dbSession.delete(resetRequest)
        dbSession.commit()
        return False
    else:
        return True


def resetPassword(dbSession, link, resetData):
    if 'passwd' not in resetData.keys():
        raise HTTPRequestError(400, 'missing password')
    try:
        resetRequest = dbSession.query(PasswordRequest). \
            filter_by(link=link).one()
        if chechRequestValidity(dbSession, resetRequest):
            user = User.getByNameOrID(resetRequest.user_id)
            user.salt, user.hash = update(dbSession, user, resetData['passwd'])

            # remove this used reset request
            PasswordRequestInactive.createInactiveFromRequest(dbSession,
                                                              resetRequest)
            dbSession.delete(resetRequest)
            return user
        else:
            raise HTTPRequestError(404, 'Page not found or expired')
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, 'Page not found or expired')


def createPasswordResetRequest(dbSession, username):
    try:
        user = dbSession.query(User). \
            filter_by(username=username).one()
    except sqlalchemy.orm.exc.NoResultFound:
        raise HTTPRequestError(404, 'User not found')

    # veify if this user have and ative password reset request
    oldRequest = dbSession.query(PasswordRequest). \
        filter_by(user_id=user.id).one_or_none()
    if oldRequest and chechRequestValidity(dbSession, oldRequest):
        raise HTTPRequestError(409, 'You have a password reset'
                                    ' request in progress')

    requestDict = {
                    'user_id': user.id,
                    'link': str(binascii.hexlify(os.urandom(16)), 'ascii')
                  }

    passwdRequest = PasswordRequest(**requestDict)
    dbSession.add(passwdRequest)

    with open('templates/passwordReset.html', 'r') as f:
        html = f.read()
    resetLink = conf.resetPwdView + '?link=' + requestDict['link']
    html = html.format(name=user.name, link=resetLink)
    sendMail(user.email, 'Password Reset', html)


def createPasswordSetRequest(dbSession, user):
    # veify if this user have an ative password reset request
    requestDict = {
                    'user_id': user.id,
                    'link': str(binascii.hexlify(os.urandom(16)), 'ascii')
                  }

    passwdRequest = PasswordRequest(**requestDict)
    dbSession.add(passwdRequest)

    with open('templates/passwordSet.html', 'r') as f:
        html = f.read()
    resetLink = conf.resetPwdView + '?link=' + requestDict['link']
    html = html.format(name=user.name,
                       link=resetLink,
                       username=user.username)
    sendMail(user.email, 'Account Activation', html)


# force expiration of one user passwords reset request
def expirePasswordResetRequests(dbSession, userid):
    resetRequest = dbSession.query(PasswordRequest). \
        filter_by(user_id=userid).one_or_none()
    if resetRequest:
            # save on inactive table before deletion
            PasswordRequestInactive.createInactiveFromRequest(dbSession,
                                                              resetRequest)
            dbSession.delete(resetRequest)
