import auth.conf as conf
from alarmlibrary.connection import RabbitMqClientConnection
from alarmlibrary.alarm import Alarm, AlarmSeverity
from database.flaskAlchemyInit import log
from database.flaskAlchemyInit import HTTPRequestError

if conf.rabbitmq_host != "DISABLED":
    rabbit_client = RabbitMqClientConnection()
    rabbit_client.open(conf.rabbitmq_host)
else:
    rabbit_client = None

class AlarmError(HTTPRequestError):

    def __init__(self, error_code, message, username, userid=0):
        """
        Publish an alarm for the HTTP2ALARM posible error codes
        """
        super().__init__(error_code, message)

        HTTP2ALARM = {
            401 : "AuthenticationError",
            403 : "AuthorizationError"
        }

        if error_code in HTTP2ALARM:
            alarm = Alarm(namespace="dojot.auth", severity=AlarmSeverity.Minor,
                          domain=HTTP2ALARM[error_code],
                          description=message)
            alarm.add_primary_subject("instance_id", "1")
            alarm.add_primary_subject("module_name", "Authentication Module")
            alarm.add_additional_data("reason", message)
            alarm.add_additional_data("username", username)
            if error_code == 401:
                alarm.add_additional_data("userid", userid)
            if rabbit_client is not None:
                try:
                    rabbit_client.send(alarm)
                except Exception as ex:
                    log().error("There was a problem with RabbitMQ connection. Error is: {ex}")
                    log().error("No alarm was sent.")
