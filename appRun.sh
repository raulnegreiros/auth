#!/bin/bash
/usr/bin/python /var/www/app/appLock.py --sleep 5 --mongo '{"database":"auth","collection":"conf"}' &> /tmp/appLock.log
/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
