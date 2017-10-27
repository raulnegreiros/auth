import logging
import requests
import binascii
import os
from requests import ConnectionError

import conf
from database.flaskAlchemyInit import HTTPRequestError

LOGGER = logging.getLogger('device-manager.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def configureKong(user):
    # Disable Kong is not advised. Only use for debug purposes
    if conf.kongURL == 'DISABLED':
        return {
                'key': 'nokey',
                'secret': str(binascii.hexlify(os.urandom(16)), 'ascii'),
                'kongid': 'noid'
                }

    try:
        exists = False
        response = requests.post('%s/consumers' % conf.kongURL,
                                 data={'username': user})
        if response.status_code == 409:
            exists = True
        elif not (response.status_code >= 200 and response.status_code < 300):
            LOGGER.error("failed to set consumer: %d %s"
                         % (response.status_code, response.reason))
            LOGGER.error(response.json())
            return None

        headers = {"content-type": "application/x-www-form-urlencoded"}
        response = requests.post('%s/consumers/%s/jwt'
                                 % (conf.kongURL, user), headers=headers)
        if not (response.status_code >= 200 and response.status_code < 300):
            LOGGER.error("failed to create key: %d %s"
                         % (response.status_code, response.reason))
            LOGGER.error(response.json())
            return None

        reply = response.json()
        return {
                'key': reply['key'],
                'secret': reply['secret'],
                'kongid': reply['id']
                }
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        return None


# Invalidate old kong shared secret
def revokeKongSecret(username, tokenId):
    if conf.kongURL == 'DISABLED':
        return
    try:
        requests.delete("%s/consumers/%s/jwt/%s"
                        % (conf.kongURL, username, tokenId))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise HTTPRequestError(500, "Failed to connect to kong")


def removeFromKong(user):
    if conf.kongURL == 'DISABLED':
        return
    try:
        requests.delete("%s/consumers/%s" % (conf.kongURL, user))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise HTTPRequestError(500, "Failed to connect to kong")
