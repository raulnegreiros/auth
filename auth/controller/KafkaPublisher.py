import base64
import requests
import logging
import json
import conf
from kafka import KafkaProducer
from kafka.errors import KafkaTimeoutError, NoBrokersAvailable

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.DEBUG)

# Global Kafka producer
kf_prod = None

# Global topic to publish tenancy lifecycle events to
tenancy_topic = None


def get_topic():
    global tenancy_topic

    if tenancy_topic:
        return tenancy_topic

    target = "{}/topic/{}?global=true".format(conf.data_broker_host, conf.kafka_subject)
    user_info = json.dumps({
        "username": "auth",
        "service": 'tenancy_management'
    })

    jwt = "{:s}.{:s}.{:s}".format(str(base64.b64encode(b"model"), 'ascii'),
                                  str(base64.b64encode(user_info.encode('ascii')), 'ascii'),
                                  str(base64.b64encode(b"signature"), 'ascii'))

    response = requests.get(target, headers={"authorization": jwt})
    if 200 <= response.status_code < 300:
        payload = response.json()
        tenancy_topic = payload['topic']
        return payload['topic']
    LOGGER.error('Failed to retrieve topic {} {}'.format(response.status_code, response.reason))
    return None


def send_notification(event):
    if kf_prod is None:
        LOGGER.warning('Tried to send a notification when there is no broker yet. Ignoring.')
        return

    try:
        topic = get_topic()
        if topic is None:
            LOGGER.error("Failed to retrieve named topic to publish to")

        kf_prod.send(topic, event)
        kf_prod.flush()
    except KafkaTimeoutError:
        LOGGER.error("Kafka timed out.")


def init():
    global kf_prod
    kf_prod = None

    if conf.kafka_host == "DISABLED" or conf.kafka_host is None:
        return

    try:
        kf_prod = KafkaProducer(value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                                bootstrap_servers=conf.kafka_host)
    except NoBrokersAvailable as e:
        LOGGER.error('No kafka brokers are available. No device event will be published.')
        LOGGER.error('Full exception is:')
        LOGGER.error('{}'.format(e))


init()
