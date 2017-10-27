#!/usr/bin/python3
import postgresql
import sys
from time import sleep

import auth.conf as dbconf

poolingsec = 5
max_retries = 10
retries = 0


def incRetries():
    global retries
    retries = retries + 1
    if retries >= max_retries:
        print("max_retries reached. Giving up...")
        exit(-1)


def waitPostgres():
    print('Waiting for postgres...')
    retries = 0
    while (True):
        try:
            db = postgresql.open('pq://'
                                 + dbconf.dbUser
                                 + ':' + dbconf.dbPdw
                                 + '@' + dbconf.dbHost)
            if db is not None:
                break
        except postgresql.exceptions.ClientCannotConnectError as e:
            print("Failed to connect to database. Error:" + str(e))

        incRetries()
        print('Will try again in ' + str(poolingsec))
        sleep(poolingsec)
    print('Postgres is ready')


def verifyParams():
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--sleep':
            global poolingsec
            poolingsec = int(sys.argv[i+1])
            i = i + 1
        if sys.argv[i] == '--max_retries':
            global max_retries
            max_retries = int(sys.argv[i+1])
            i = i + 1

        i = i + 1


if __name__ == '__main__':
    verifyParams()
    waitPostgres()
    exit(0)
