FROM python:3.6

RUN pip3 install cython

RUN mkdir -p /usr/src/app/requirements && mkdir /usr/src/app/auth \
    && wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10_million_password_list_top_1000000.txt \
    && cat 10_million_password_list_top_1000000.txt \
      | sed -r '/^.{,5}$/d'  > /usr/src/app/auth/password_blacklist.txt

WORKDIR /usr/src/app

ADD . /usr/src/app
RUN ["python3", "setup.py", "develop"]

EXPOSE 5000
CMD ["./appRun.sh", "start"]
