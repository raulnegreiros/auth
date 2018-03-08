#!/bin/bash

set -e

# emulate device-manager initial configuration
echo Running waitForDb
python3 ./tests/waitForDb.py
echo waitForDb ok

echo Running appLock.py
# wait for database
python3 ./appLock.py --sleep 10 --max_retries 3
rc=$?; if [[ ${rc} != 0 ]]; then exit ${rc}; fi
echo appLock.py ok

cd auth

echo Creating model databases
# create database tables
python3 -c "from webRoutes import db; db.create_all()"
echo model databases ok

echo Running initialConf.py
# create predefined users and groups
python3 ./initialConf.py
rc=$?; if [[ ${rc} != 0 ]]; then exit ${rc}; fi
echo initialConf.py ok

cd ..
echo Starting dredd
for file in "./docs/auth.apib" "./docs/crud-api.apib" "./docs/relation.apib" "./docs/report.apib"; do
    dredd --hookfiles "./tests/dredd-hooks/*hook.py" --server "gunicorn auth.webRoutes:app --bind 0.0.0.0:5000" --language python ${file} http://127.0.0.1:5000
done
