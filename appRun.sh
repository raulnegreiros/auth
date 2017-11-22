#!/bin/bash

# wait for database
python3 /usr/src/app/appLock.py --sleep 10 --max_retries 3
rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi

cd auth

# create database tables
python3 -c "from webRoutes import db; db.create_all()"   2> /dev/null

# create predefined users and groups
python3 /usr/src/app/auth/initialConf.py
rc=$?; if [[ $rc != 0 ]]; then exit $rc; fi

# handle service initialization
if [ $1 = 'start' ]; then
    flag=0
    retries=0
    max_retries=5
    sleep_time=5
    while [ $flag -eq 0 ]; do
        if [ $retries -eq $max_retries ]; then
            echo Executed $retries retries, aborting
            exit 1
        fi
        sleep $sleep_time
        exec gunicorn webRoutes:app \
                  --bind 0.0.0.0:5000 \
                  --reload -R \
                  --access-logfile - \
                  --log-file - \
                  --env PYTHONUNBUFFERED=1 -k gevent 2>&1

        if [ $? -eq 0 ]; then
            flag=1
        else
            echo "Cannot start application, retying in $sleep_time seconds..."
            let retries++
        fi
    done
fi
