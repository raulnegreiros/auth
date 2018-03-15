# dojot Authentication service

This service handles user authentication for the platform. Namely this is used to
maintain the set of known users, and their associated roles. Should a user need
to interact with the platform, this service is responsible for generating the JWT
token to be used when doing so.

## Installation

This service depends on a couple of python libraries to work. To install them, please run the
commands below. These have been tested on an ubuntu 16.04 environment (same used when generating)
the service's docker image.

```shell
# you may need sudo for those
apt-get install -y python3-pip
python3 setup.py
```

Another alternative is to use docker to run the service. To build the container, from the
repository's  root:

```shell
# you may need sudo on your machine: https://docs.docker.com/engine/installation/linux/linux-postinstall/
docker build -t <tag> -f docker/Dockerfile .
```

## Configuration

### Database related configuration

Some auth configuration is made using environment variables.
On a Linux system one can set a environment variable with the command

```shell
  export VAR_NAME=varvalue
```

on a docker-compose schema, one can set environment variables for a container
Append the following configuration

```shell
  environment:
      VAR_NAME: "varvalue"
```

The default value is used if the configuration was not provided
The following variables can be set

* AUTH_DB_NAME
  * database type. Current only postgres is supported
  * default: postgres

  * AUTH_DB_USER
    * The username used to access the database
    * default: auth

  * AUTH_DB_PWD
        * The password used to access the database
        * default: empty password

  * AUTH_DB_HOST
        * The URL used to connect to the database
        * default: http://postgres

  * AUTH_KONG_URL
        * The URL where the Kong service can be found
        * If set to 'DISABLED' Auth won´t try to configure Kong and will generate secrets for the JWT tokens by itself.
        * default: http://Kong:8001

  * AUTH_TOKEN_EXP
        * Expiration time in second for generated JWT tokens
        * default: 420

  * AUTH_TOKEN_CHECK_SIGN
        * Whether Auth should verify received JWT signatures. Enabling this will cause one extra query to be performed.
        * default: False

  * AUTH_CACHE_NAME
        * Type of cache used. Currently only Redis is suported.
        * If set to 'NOCACHE' auth will work without cache. Disabling cache usage considerably degrades performance.
        * default: redis

  * AUTH_CACHE_USER
        * username to access the cache database
        * default: redis

  * AUTH_CACHE_PWD
        * password to acces the cache database
        * default: empty password

  * AUTH_CACHE_HOST
        * ip or hostname where the cache can be found
        * default: redis

  * AUTH_CACHE_TTL
        * Cache entry time to live in seconds
        * default: 720

  * AUTH_CACHE_DATABASE
        * cach database name (or number)
        * default: '0'

If you are running without docker, You will need to create and populate
the database tables before the first run.

python3 shell:

```shell
>>> from webRouter import db
>>> db.create_all()
```

Create the initial users, groups and permissions

```shell
  python3 initialConf.py
```

## API

The API documentation for this service is written as API blueprints.
To generate a simple web page from it, one may run the commands below.

```shell
npm install -g aglio # you may need sudo for this

# static webpage
aglio -i docs/auth.apib -o docs/auth.html

# serve apis locally
aglio -i docs/auth.apib -s
```

## Tests

Auth has some automated test scripts.
We use [pyresttest](https://github.com/svanoort/pyresttest) format for the test schemas.
Tests should be run with DISABLED Kong and DISABLED JWT signature verification.
You can run the test with:

```shell
python resttest.py "http://authhost:port" test/<TEST_FILE>.yaml
```
