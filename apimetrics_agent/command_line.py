#!/usr/bin/env python
from __future__ import print_function
import datetime as dt
import logging
import os
import json
import sys
import argparse
from azure.servicebus import QueueClient
from .config import Config
from .register import register_agent_with_gae
from .thread import handle_request

logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s:%(name)s:%(lineno)s: %(levelname)s: %(message)s",
    level=os.environ.get("DEBUG_LEVEL") or logging.INFO,
)

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Path to the config file")
    parser.add_argument(
        "--show_settings",
        "-s",
        help="Show settings only, don't run",
        action="store_true",
    )
    parser.add_argument(
        "--taskqueue_name", "-t", help="Set the APImetrics taskqueue name"
    )
    parser.add_argument("--display_name", "-d", help="Set the APImetrics display name")
    parser.add_argument("--user", "-u", help="Set the APImetrics username")
    parser.add_argument("--access_token", "-a", help="Set the APImetrics access token")
    parser.add_argument("--host_url", "-host", help="Set the APImetrics host url")
    parser.add_argument(
        "--key_name", "-key", help="Set the Service Bus access key name"
    )
    parser.add_argument(
        "--key_value", "-value", help="Set the Service Bus access key value"
    )
    parser.add_argument(
        "--ssl_cert_file", "-cert", help="Certificate file for 2-way SSL"
    )
    parser.add_argument(
        "--ssl_key_file", "-pem", help="Certificate key (PEM) file for 2-way SSL"
    )

    args = vars(parser.parse_args())

    config_file = None
    if args["config"]:
        config_file = args["config"]
    config = Config()
    config.load_from_file(config_file)
    if config.update(args):
        run(config=config)


def get_callback(listener, msg):
    msg_id = (
        msg.broker_properties.get("MessageId", "??")
        if msg and msg.broker_properties
        else "?"
    )

    def cb_func(*args, **kwargs):
        logger.info("Success callback for msg %s: %s %s", msg_id, args, kwargs)
        return listener.mark_message_as_complete(msg)

    return cb_func


def get_error_callback(listener, msg):
    msg_id = (
        msg.broker_properties.get("MessageId", "??")
        if msg and msg.broker_properties
        else "?"
    )

    def cb_func(*args, **kwargs):
        logger.warning("Error callback for msg %s: %s %s", msg_id, args, kwargs)

    return cb_func


def extract_defintion(msg):
    logger.debug("extract_defintion %s %s", msg, msg.body)
    if msg and msg.body is not None:
        bytes_arr = next(msg.body)
        json_string = bytes_arr.decode("utf-8")
        output = json.loads(json_string)
        return output


def listen(config):

    queue_client = QueueClient.from_connection_string(
        config.azure.connection_string, config.azure.taskqueue
    )

    last_message = dt.datetime.utcnow()
    diff = 0
    while diff < (60 * 15):
        logger.info(
            "Last msg %s - creating receiver for %s", diff, config.azure.taskqueue
        )
        with queue_client.get_receiver(idle_timeout=60*5) as messages:
            for message in messages:  # pylint: disable=not-an-iterable
                last_message = dt.datetime.utcnow()
                definiton = extract_defintion(message)
                if definiton:
                    url, _, _ = (
                        definiton.get("request", {}).get("url", "").partition("?")
                    )
                    logger.info("Request received for %s", url)
                    handle_request(config, definiton, complete_cb=message.complete)
            else: 
                logger.info("... no message")

            now = dt.datetime.utcnow()
            diff = (now - last_message).total_seconds()


def run(config):

    try:
        register_agent_with_gae(config)
    except Exception as ex:  # pylint: disable=W0703
        print(ex)
        sys.exit(1)

    logger.debug("DEBUG_LEVEL: %s", os.environ.get("DEBUG_LEVEL"))
    logger.debug(
        "GOOGLE_APPLICATION_CREDENTIALS: %s",
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"),
    )

    listen(config)


if __name__ == "__main__":
    main()
