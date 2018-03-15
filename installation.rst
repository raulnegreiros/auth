Installation
============

This service depends on a couple of python libraries to work. To install them,
please run the commands below. These have been tested on an ubuntu 16.04
environment (same used when generating) the service's docker image.

.. code-block:: shell
  
   # you may need sudo for those
   apt-get install -y python3-pip
   python3 setup.py


Another alternative is to use docker to run the service. To build the
container, from the repository's root:

.. code-block:: shell
  
   # you may need sudo on your machine: https://docs.docker.com/engine/installation/linux/linux-postinstall/
   docker build -t <tag> -f docker/Dockerfile .
