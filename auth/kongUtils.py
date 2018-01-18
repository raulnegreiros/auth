import logging
import requests
import binascii
import os
from requests import ConnectionError

import conf
from database.flaskAlchemyInit import HTTPRequestError

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def configure_kong(user):
    # Disable Kong is not advised. Only use for debug purposes
    if conf.kongURL == 'DISABLED':
        return {
                'key': 'nokey',
                'secret': str(binascii.hexlify(os.urandom(16)), 'ascii'),
                'kongid': 'noid'
                }

    try:
        response = requests.post('%s/consumers' % conf.kongURL,
                                 data={'username': user})
        if response.status_code == 409:
            LOGGER.warning("Consumer already exists")
        elif not (200 <= response.status_code < 300):
            LOGGER.error("failed to set consumer: %d %s"
                         % (response.status_code, response.reason))
            LOGGER.error(response.json())
            return None

        headers = {"content-type": "application/x-www-form-urlencoded"}
        response = requests.post('%s/consumers/%s/jwt'
                                 % (conf.kongURL, user), headers=headers)
        if not (200 <= response.status_code < 300):
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
def revoke_kong_secret(username, token_id):
    if conf.kongURL == 'DISABLED':
        return
    try:
        requests.delete("%s/consumers/%s/jwt/%s"
                        % (conf.kongURL, username, token_id))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise HTTPRequestError(500, "Failed to connect to kong")


def remove_from_kong(user):
    if conf.kongURL == 'DISABLED':
        return
    try:
        requests.delete("%s/consumers/%s" % (conf.kongURL, user))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise HTTPRequestError(500, "Failed to connect to kong")
