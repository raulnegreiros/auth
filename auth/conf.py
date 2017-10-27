# This file contains the default configuration values
# and confiuration retrivement functions

import os


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

# if auth should verify JWT signatures. Ative this will cause one
# query of overhead.
checkJWTSign = (os.environ.get("AUTH_TOKEN_CHECK_SIGN", "FALSE") in
                ['true', 'True', 'TRUE'])
