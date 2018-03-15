dojot Authentication service
============================

|License badge| |Docker badge|

This service handles user authentication for `dojot`_. Namely this is used to
maintain the set of known users, and their associated roles. Should a user need
to interact with the platform, this service is responsible for generating the
JWT token to be used when doing so.

.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :glob:

   installation
   configuration
   api
   building-documentation

.. Indices and tables
.. ==================
..
.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`


.. |License badge| image:: https://img.shields.io/badge/license-GPL-blue.svg
   :target: https://opensource.org/licenses/GPL-3.0
.. |Docker badge| image:: https://img.shields.io/docker/pulls/dojot/auth.svg
   :target: https://hub.docker.com/r/dojot/auth/

.. _dojot: https://github.com/dojot/dojot
