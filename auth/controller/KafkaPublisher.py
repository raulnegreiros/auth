import base64
import requests
import logging
import json
from conf import kafka_subject, kafka_host, data_broker_host
from dojot.module import Messenger, Config, Log
import threading 

LOGGER = Log().color_log()
messenger = None


def send_notification(event):
    global messenger
    LOGGER.debug("Publishing event: " + kafka_host + ", " + kafka_subject + ": " + json.dumps(event))
    try:
        messenger.publish(kafka_subject, "dojot-management", event)
    except Exception as e:
        LOGGER.debug("Caught: " + str(e))
    finally:
        LOGGER.debug("data published")
    
def init():
    global messenger
    LOGGER.debug("Initializing dojot.module")
    config = Config({
        "kafka" : {
            "producer": {
                "client.id": "dojot.auth",
                "metadata.broker.list": kafka_host,
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
                "group.id": "dojot.auth",
                "metadata.broker.list": kafka_host
            }
        },
        "data_broker" : {
            "url": data_broker_host
        },
        "auth" : {
            "url": "http://localhost:5000"
        }
    })

    LOGGER.debug("Config is:  " + json.dumps(config.data_broker))
    messenger = Messenger("dojot.auth", config)
    LOGGER.debug("Initializing messenger")
    messenger.init()
    LOGGER.debug("... messenger initialized.")
    LOGGER.debug("Creating channel " + kafka_subject)
    messenger.create_channel(kafka_subject, "w")

class InitKafkaThread(threading.Thread):
    def run(self):
        init()


initKafkaThr = InitKafkaThread()
initKafkaThr.start()
