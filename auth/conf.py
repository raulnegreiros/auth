# This file contains the default configuration values
# and confiuration retrivement functions

import os


# database related configuration
dbName = os.environ.get("DB_NAME", "postgres")
dbUser = os.environ.get("DB_USER", "auth")
dbPdw = os.environ.get("DB_PWD", "")
dbHost = os.environ.get("DB_HOST", "postgres")


# kong related configuration
kongURL = os.environ.get("KONG_URL", "http://kong:8001")


# JWT token related configuration
tokenExpiration = int(os.environ.get("TOKEN_EXP", 420))
