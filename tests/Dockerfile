FROM dojot/dredd-python:3.6

RUN pip3 install cython

RUN mkdir -p /usr/src/app/requirements && mkdir /usr/src/app/auth && mkdir /usr/src/app/tests

WORKDIR /usr/src/app

ADD . /usr/src/app
RUN pip install -r requirements/requirements.txt
RUN pip install -r /usr/src/app/tests/requirements.txt
RUN ["python3", "setup.py", "develop"]

ENV PYTHONPATH=${PYTHONPATH}:/usr/src/app/auth
CMD ["./tests/start-test.sh"]
