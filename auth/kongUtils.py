import logging
import requests
from requests import ConnectionError
from conf import getConfValue

LOGGER = logging.getLogger('device-manager.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def configureKong(user):
    kong = getConfValue('kongURL')
    try:
        exists = False
        response = requests.post('%s/consumers' % kong, data={'username': user})
        if response.status_code == 409:
            exists = True
        elif not (response.status_code >= 200 and response.status_code < 300):
            LOGGER.error("failed to set consumer: %d %s" % (response.status_code, response.reason))
            LOGGER.error(response.json())
            return None

        headers = {"content-type":"application/x-www-form-urlencoded"}
        response = requests.post('%s/consumers/%s/jwt' % (kong, user), headers=headers)
        if not (response.status_code >= 200 and response.status_code < 300):
            LOGGER.error("failed to create key: %d %s" % (response.status_code, response.reason))
            LOGGER.error(response.json())
            return None

        reply = response.json()
        return {'key': reply['key'], 'secret': reply['secret'], 'kongid': reply['id']}
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        return None

#invalidate old kong shared secret
def revokeKongSecret(username, tokenId):
    kong = getConfValue('kongURL')
    try:
        requests.delete("%s/consumers/%s/jwt/%s" % (kong, username, tokenId))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise


def removeFromKong(user):
    kong = getConfValue('kongURL')
    try:
        requests.delete("%s/consumers/%s" % (kong, user))
    except ConnectionError:
        LOGGER.error("Failed to connect to kong")
        raise
