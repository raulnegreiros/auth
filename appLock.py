#!/usr/bin/python3
import postgresql
from postgresql import exceptions
from time import sleep
from argparse import ArgumentParser

import auth.conf as dbconf


def wait_postgres(polling_sec, max_retries):
    print('Waiting for postgres...')

    retries = 0
    while retries < max_retries:
        try:
            db = postgresql.open('pq://'
                                 + dbconf.dbUser
                                 + ':' + dbconf.dbPdw
                                 + '@' + dbconf.dbHost)
            if db is not None:
                print('Postgres is ready')
                return 0

        except exceptions.ClientCannotConnectError as e:
            print("Failed to connect to database. Error:" + str(e))

        retries = retries + 1
        print('Will try again in ' + str(polling_sec))
        sleep(polling_sec)

    print("Max retries reached. Giving up...")
    return 1


def verify_params():

    parser = ArgumentParser()

    # Add more options if you like
    parser.add_argument("-s", "--sleep", dest="polling_sec", action="store", default=5,
                        help="Retries interval in seconds", type=int)

    parser.add_argument("-r", "--max_retries", dest="max_retries",
                        action="store", default=10,
                        help="Maximum number of retries", type=int)

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    params = verify_params()
    ret = wait_postgres(params.polling_sec, params.max_retries)
    exit(ret)
