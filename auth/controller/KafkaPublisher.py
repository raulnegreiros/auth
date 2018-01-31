import base64
import requests
import logging
import json
import conf
from kafka import KafkaProducer
from kafka.errors import KafkaTimeoutError

LOGGER = logging.getLogger('auth.' + __name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.DEBUG)

kf_prod = KafkaProducer(value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                        bootstrap_servers=conf.kafka_host)

# Global topic to publish tenancy lifecycle events to
tenancy_topic = None

def get_topic():
    global tenancy_topic
    if tenancy_topic:
        return tenancy_topic

    target = "{}/topic/{}?global=true".format(conf.data_broker_host, conf.kafka_subject)
    userinfo = json.dumps({
        "username": "auth",
        "service": 'tenancy_management'
    })

    jwt = "{:s}.{:s}.{:s}".format(str(base64.b64encode(b"model"), 'ascii'),
                                  str(base64.b64encode(userinfo.encode('ascii')), 'ascii'),
                                  str(base64.b64encode(b"signature"), 'ascii'))

    response = requests.get(target, headers={"authorization": jwt})
    if 200 <= response.status_code < 300:
        payload = response.json()
        tenancy_topic = payload['topic']
        return payload['topic']
    LOGGER.error('Failed to retrieve topic {} {}'.format(response.status_code, response.reason))
    return None


def send_notification(event):
    # TODO What if Kafka is not yet up?
    try:
        topic = get_topic()
        if topic is None:
            LOGGER.error("Failed to retrieve named topic to publish to")

        kf_prod.send(topic, event)
        kf_prod.flush()
    except KafkaTimeoutError:
        LOGGER.error("Kafka timed out.")
