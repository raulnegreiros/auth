FROM python:3.6-alpine
# RUN apk add --no-cache gcc libc-dev unixodbc-dev py-psycopg2

RUN apk update && apk --no-cache add build-base postgresql-dev libffi-dev git libc6-compat linux-headers bash dumb-init

RUN pip install cython

RUN mkdir -p /usr/src/app/requirements && mkdir /usr/src/app/auth

WORKDIR /usr/src/app

ADD ./requirements/requirements.txt /usr/src/app/requirements/
RUN pip install -r requirements/requirements.txt && apk del gcc

ADD . /usr/src/app

EXPOSE 5000
CMD ["./appRun.sh", "start"]
