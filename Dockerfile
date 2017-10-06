FROM python:3

RUN pip3 install cython

RUN mkdir -p /usr/src/app/requirements
WORKDIR /usr/src/app

ADD . /usr/src/app
RUN ["python3", "setup.py", "develop"]

EXPOSE 5000
CMD ["./appRun.sh", "start"]
