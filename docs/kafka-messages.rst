Internal messages
=================

There are some messages that are published by Auth through Kafka.
These messages are related to tenancy lifecycle events.

.. list-table:: Kafka messages
   :header-rows: 1

   * - Event
     - Subject
     - Service
     - Message type
   * - Tenant creation
     - dojot.tenancy
     - internal
     - `Tenant creation`_
   * - Tenant removal
     - dojot.tenancy
     - internal
     - `Tenant removal`_


Tenant creation
---------------

This message is published whenever a new tenant is created.
Its payload is a simple JSON:

.. code-block:: json

    {
      "type": "CREATE",
      "tenant": "admin"
    }

And its attributes are:

- *type* (string): "CREATE"
- *tenant*: New tenant

Tenant removal
---------------

This message is published whenever a new tenant is removed.
Its payload is a simple JSON:

.. code-block:: json

    {
      "type": "DELETE",
      "tenant": "admin"
    }

And its attributes are:

- *type* (string): "DELETE"
- *tenant*: New tenant
