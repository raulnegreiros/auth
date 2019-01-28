import base64
import requests
import logging
import json
from conf import kafka_subject, kafka_host, data_broker_host
from dojot.module import Messenger, Config, Log
import threading
import time

LOGGER = Log().color_log()

class Publisher(threading.Thread):
    messenger = None

    @classmethod
    def send_notification(cls, event):
        if cls.messenger is None:
            return

        LOGGER.debug("Publishing event: " + kafka_host + ", " + kafka_subject + ": " + json.dumps(event))
        try:
            cls.messenger.publish(kafka_subject, "dojot-management", event)
        except Exception as e:
            LOGGER.debug("Caught: " + str(e))
        finally:
            LOGGER.debug("data published")

    @classmethod
    def init(cls):
        if cls.messenger is not None:
            return

        LOGGER.debug("Initializing dojot.module")
        config = Config({
            "kafka" : {
                "producer": {
                    "client.id": "dojot.auth",
                    "bootstrap_servers": [kafka_host],
                    "compression.codec": "gzip",
                    "retry.backoff.ms": 200,
                    "message.send.max.retries": 10,
                    "socket.keepalive.enable": True,
                    "queue.buffering.max.messages": 100000,
                    "queue.buffering.max.ms": 1000,
                    "batch.num.messages": 1000000,
                    "dr_cb": True
                },
                "consumer": {
                    "group_id": "dojot.auth",
                    "bootstrap_servers": [kafka_host]
                }
            },
            "data_broker" : {
                "url": data_broker_host,
                "connection_retries": 3,
                "timeout_sleep": 5
            },
            "auth" : {
                "url": "http://localhost:5000",
                "connection_retries": 3,
                "timeout_sleep": 5
            }
        })

        LOGGER.debug("Config is:  " + json.dumps(config.auth))
        cls.messenger = Messenger("dojot.auth", config)
        LOGGER.debug("Initializing messenger")
        cls.messenger.init()
        LOGGER.debug("... messenger initialized.")
        LOGGER.debug("Creating channel " + kafka_subject)
        cls.messenger.create_channel(kafka_subject, "w")

    def run(self):
        self.init()
