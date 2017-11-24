# Redis cache configuration
# powered by flask-redis: https://github.com/underyx/flask-redis

from flask_redis import FlaskRedis
import redis
import logging

import conf
from .flaskAlchemyInit import app, db

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


if (conf.cacheName == 'redis'):
    REDIS_URL = ('redis://' + conf.cacheUser + ':' + conf.cachePdw
                 + '@' + conf.cacheHost + ':6379/' + conf.cacheDatabase)
    app.config['DBA_URL'] = REDIS_URL
    redis_store = FlaskRedis(app, config_prefix='DBA', strict=False,
                             encoding="utf-8", socket_keepalive=True,
                             charset="utf-8", decode_responses=True)


elif (conf.cacheName == 'NOCACHE'):
    LOGGER.warning("Warning. Cache policy set to NOCACHE."
                   "This may degrade PDP perfomance.")
    redis_store = None

else:
    LOGGER.error("Currently, there is no suport for cache policy "
                 + conf.dbName)
    exit(-1)


# create a cache key
def generateKey(userid, action, resource):
    # add a prefix to every key, to avoid colision with others aplications
    key = 'PDP;'
    key += str(userid) + ';' + action + ';' + resource
    return key


# utility function to get a value on redis
# return None if the value can't be found
def getKey(userid, action, resource):
    if redis_store:
        try:
            cachedValue = redis_store. \
                            get(generateKey(userid, action, resource))
            return cachedValue
        except redis.exceptions.ConnectionError:
            LOGGER.warning("Failed to connect to redis")
            return None


def setKey(userid, action, resource, veredict):
    try:
        redis_store.setex(generateKey(
                                        userid,
                                        action,
                                        resource
                                      ),
                          str(veredict),
                          conf.cacheTtl   # time to live
                          )
    except redis.exceptions.ConnectionError:
        LOGGER.warning("Failed to connect to redis")


# invalidate a key. may use regex patterns
def deleteKey(userid='*', action='*', resource='*'):
    if redis_store:
        # python-RE and Redis use diferent wildcard representations
        action = action.replace('(.*)', '*')
        resource = resource.replace('(.*)', '*')
        # TODO: put the cache update on a worker threaded
        key = generateKey(userid, action, resource)
        try:
            for dkey in redis_store.scan_iter(key):
                redis_store.delete(dkey)
        except redis.exceptions.ConnectionError:
            LOGGER.warning("Failed to connect to redis")
