#this file contains the default configuration values
#and confiuration retrivement functions

import os

# database related configuration
try:
    dbName = os.environ['DB_NAME']
except KeyError:
    dbName = "postgres"

try:
    dbUser = os.environ['DB_USER']
except KeyError:
    dbUser = "pyrbac"

try:
    dbPdw = os.environ['DB_PWD']
except KeyError:
    dbPdw = "pwd12"

try:
    dbHost = os.environ['DB_HOST']
except KeyError:
    dbHost = "localhost"


# kong related configuration
try:
    kongURL = os.environ['KONG_URL']
except KeyError:
    kongURL = 'http://localhost:8001' #'http://kong:8001'

# JWT token related configuration
try:
    tokenExpiration = int( os.environ['TOKEN_EXP'] )
except KeyError:
    tokenExpiration =  420
