# This file contains function that implement password
# related policies

import logging
import binascii
from pbkdf2 import crypt
import os
import sqlalchemy
import datetime
from difflib import SequenceMatcher
from marisa_trie import Trie

from database.flaskAlchemyInit import HTTPRequestError
from database.historicModels import PasswdInactive, PasswordRequestInactive
from database.Models import PasswordRequest, User
from utils.emailUtils import sendMail
import conf

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


# read a password blacklist file
# and put these password on a trie
def loadPasswordBlacklist():
    global passwdBlackList
    if conf.passwdBlackList == 'NOBLACKLIST':
        LOGGER.warning('No password blacklist file defined.')
        passwdBlackList = Trie()
        return

    if os.path.isfile('compiledPwdBlacklist.bin'):
        LOGGER.info('Loading pre-compiled password blacklist...')
        passwdBlackList = Trie()
        passwdBlackList.load('compiledPwdBlacklist.bin')

    else:
        try:
            LOGGER.info('Compiling password blacklist...')
            with open(conf.passwdBlackList, encoding="utf-8") as f:
                pwds = f.read().splitlines()
                passwdBlackList = Trie(pwds)
            passwdBlackList.save('compiledPwdBlacklist.bin')
        except FileNotFoundError:
            LOGGER.error('File ' + conf.passwdBlackList
                         + ' not found. Aborting.')
            exit(-1)


# load password blacklist on startup
loadPasswordBlacklist()


# check if a password is obvious weak
# throws a exception if the password fail a test
def checkPaswordFormat(user, passwd):
    passwdLen = len(passwd)
    if passwdLen < conf.passwdMinLen:
        raise HTTPRequestError(400, 'password must have at least '
                                    + str(conf.passwdMinLen)
                                    + ' characters')
    if passwdLen > 512:
        raise HTTPRequestError(400, 'Calm down! 512 characters is the '
                                    ' maximum password len')
    lowerPwd = passwd.lower()

    # check if the password can be guessed with user info
    if (
            SequenceMatcher(None, lowerPwd, user.username)
            .find_longest_match(0, passwdLen, 0, len(user.username))
            .size > 4
            or
            SequenceMatcher(None, lowerPwd, user.email)
            .find_longest_match(0, passwdLen, 0, len(user.email))
            .size > 4
            or
            SequenceMatcher(None, lowerPwd, user.name.lower())
            .find_longest_match(0, passwdLen, 0, len(user.name.lower()))
            .size > 4):
        raise HTTPRequestError(400, 'Please, choose a password'
                                    ' harder to guess. Your user info may'
                                    ' give hints on this password')

    # check for dull sequences
    # like 'aaa' '123' 'abc'
    lastChar = '\0'
    countEquals = 1
    countUp = 1
    countDown = 1
    for c in passwd:
        if (ord(c) == ord(lastChar) + 1):
            countUp += 1
        else:
            countUp = 1

        if (ord(c) == ord(lastChar) - 1):
            countDown += 1
        else:
            countDown = 1

        if (c == lastChar):
            count += 1
        else:
            count = 1

        if count == 3 or countUp == 3 or countDown == 3:
            raise HTTPRequestError(400, 'do not use passwords with '
                                        ' easy to guess'
                                        ' character sequences')

        lastChar = c

    # check vs a blacklist
    if passwd in passwdBlackList:
        raise HTTPRequestError(400, "This password can't be used, as it is "
                                    " in our blacklist of bad passwords")


def createPwd(passwd):
    salt = str(binascii.hexlify(os.urandom(8)), 'ascii')
    hash = crypt(passwd, salt, 1000).split('$').pop()
    return salt, hash


# update a passwd.
# verify if the new passwd was used before
# save the current passwd on inative table
def update(dbSession, user, newPasswd):
    checkPaswordFormat(user, newPasswd)

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
    return createPwd(newPasswd)


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
