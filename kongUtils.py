import requests
from requests import ConnectionError

global kong

def configureKong(user):
    try:
        exists = False
        response = requests.post('%s/consumers' % kong, data={'username': user})
        if response.status_code == 409:
            exists = True
        elif not (response.status_code >= 200 and response.status_code < 300):
            print ("failed to set consumer: %d %s" % (response.status_code, response.reason))
            print (response.json())
            return None

        headers = {"content-type":"application/x-www-form-urlencoded"}
        response = requests.post('%s/consumers/%s/jwt' % (kong, user), headers=headers)
        if not (response.status_code >= 200 and response.status_code < 300):
            print ("failed to create key: %d %s" % (response.status_code, response.reason))
            print (response.json())
            return None

        reply = response.json()
        return { 'key': reply['key'], 'secret': reply['secret'], 'kongid': reply['id'] }
    except ConnectionError:
        print("Failed to connect to kong")
        return None

#invalidate old kong shared secret
def revokeKongSecret(username, tokenId):
    try:
        requests.delete("%s/consumers/%s/jwt/%s" % (kong, username, tokenId))
    except ConnectionError:
        print "Failed to connect to kong"
        raise


def removeFromKong(user):
    try:
        requests.delete("%s/consumers/%s" % (kong, user))
    except ConnectionError:
        print "Failed to connect to kong"
        raise
