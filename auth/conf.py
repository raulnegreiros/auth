# This file contains the default configuration values
# and configuration retrieval functions

import logging
import os

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

# database related configuration
dbName = os.environ.get("AUTH_DB_NAME", "postgres")
dbUser = os.environ.get("AUTH_DB_USER", "auth")
dbPdw = os.environ.get("AUTH_DB_PWD", "")
dbHost = os.environ.get("AUTH_DB_HOST", "postgres")


# cache related configuration
cacheName = os.environ.get("AUTH_CACHE_NAME", "redis")
cacheUser = os.environ.get("AUTH_CACHE_USER", "redis")
cachePdw = os.environ.get("AUTH_CACHE_PWD", "")
cacheHost = os.environ.get("AUTH_CACHE_HOST", "redis")
cacheTtl = int(os.environ.get("AUTH_CACHE_TTL", 720))
cacheDatabase = os.environ.get("AUTH_CACHE_DATABASE", "0")

# kong related configuration
kongURL = os.environ.get("AUTH_KONG_URL", "http://kong:8001")


# JWT token related configuration
tokenExpiration = int(os.environ.get("AUTH_TOKEN_EXP", 420))

# email related configuration
emailHost = os.environ.get("AUTH_EMAIL_HOST", "NOEMAIL")
emailPort = int(os.environ.get("AUTH_EMAIL_PORT", 587))
emailTLS = (os.environ.get("AUTH_EMAIL_TLS", "true") in
            ['true', 'True', 'TRUE'])
emailUsername = os.environ.get("AUTH_EMAIL_USER", "")
emailPasswd = os.environ.get("AUTH_EMAIL_PASSWD", "")

# if you are using a front end with Auth,
# define this link to point to the password reset view on you FE
resetPwdView = os.environ.get("AUTH_RESET_PWD_VIEW",
                              "https://localhost:5000/password/resetlink")

# if EMAIL_HOST is set to NOEMAIL a temporary password is given to
# new users
temporaryPassword = os.environ.get("AUTH_USER_TMP_PWD", "temppwd")


# password policies configuration
# time to expire an password reset link in minutes
passwdRequestExpiration = int(os.environ.get("AUTH_PASSWD_REQUEST_EXP", 30))
# how many passwords should be check on the user history
# to enforce no password repetition policy
passwdHistoryLen = int(os.environ.get("AUTH_PASSWD_HISTORY_LEN", 4))

passwdMinLen = int(os.environ.get("AUTH_PASSWD_MIN_LEN", 8))


password_blackList = os.environ.get("AUTH_PASSWD_BLACKLIST",
                                    "password_blacklist.txt")


logMode = os.environ.get("AUTH_SYSLOG", "STDOUT")


# make some configuration checks
# and warn if dangerous configuration is found
if emailHost == 'NOEMAIL':
    LOGGER.warning("MAIL_HOST set to NOEMAIL. This is unsafe"
                   " and there's no way to reset users forgotten password")
else:
    if not emailUsername or not emailPasswd:
        LOGGER.warning('Invalid configuration: No AUTH_EMAIL_USER or AUTH_EMAIL_PASSWD'
                       ' defined although a AUTH_EMAIL_HOST was defined')

    if not emailTLS:
        LOGGER.warning('Using e-mail without TLS is not safe')

if passwdMinLen < 6:
    LOGGER.warning("Password minlen can't be less than 6.")
    passwdMinLen = 6
