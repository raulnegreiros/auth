Configuration
=============

Database related configuration
------------------------------

Some auth configuration is made using environment variables. On a Linux system
one can set a environment variable with the command

.. code-block:: bash

   export VAR_NAME=varvalue


on a docker-compose schema, one can set environment variables for a container
Append the following configuration

.. code-block:: yaml

   environment:
     VAR_NAME: "varvalue"


The default value is used if the configuration was not provided
The following variables can be set


.. list-table:: Environment variable
  :header-rows: 1

  * - Variable
    - Description
    - Default value
  * - AUTH_DB_NAME
    - database type. Current only postgres is supported
    - postgres
  * - AUTH_DB_USER
    - The username used to access the database
    - auth
  * - AUTH_DB_PWD
    - The password used to access the database
    - empty password
  * - AUTH_DB_HOST
    - The URL used to connect to the database
    - http://postgres
  * - AUTH_KONG_URL
    - The URL where the Kong service can be found. If set to 'DISABLED' Auth won´t try to configure Kong and will generate secrets for the JWT tokens by itself.
    - http://kong:8001
  * - AUTH_TOKEN_EXP
    - Expiration time in second for generated JWT tokens
    - 420
  * - AUTH_TOKEN_CHECK_SIGN
    - Whether Auth should verify received JWT signatures. Enabling this will cause one extra query to be performed.
    - False
  * - AUTH_CACHE_NAME
    - Type of cache used. Currently only Redis is suported. If set to 'NOCACHE' auth will work without cache. Disabling cache usage considerably degrades performance.
    - redis
  * - AUTH_CACHE_USER
    - username to access the cache database
    - redis
  * - AUTH_CACHE_PWD
    - password to acces the cache database
    - empty password
  * - AUTH_CACHE_HOST
    - ip or hostname where the cache can be found
    - redis
  * - AUTH_CACHE_TTL
    - Cache entry time to live in seconds
    - 720
  * - AUTH_CACHE_DATABASE
    - cach database name (or number)
    - '0'
  
If you are running without docker, You will need to create and populate the
database tables before the first run. This can be done by executing the following commands in python3 shell:

.. code-block:: python3

   >>> from webRouter import db
   >>> db.create_all()


Create the initial users, groups and permissions

.. code-block:: bash

   python3 initialConf.py
