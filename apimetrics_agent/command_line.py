#!/usr/bin/env python
from __future__ import print_function
import datetime as dt
import logging
import os
import json
import sys
import argparse

from azure.servicebus import ServiceBusClient
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


def extract_defintion(body):
    logger.debug("extract_defintion")
    try:
        json_string = body.decode("utf-8")
        output = json.loads(json_string)
        return output
    except Exception as ex:
        logger.error("Failed to parse message body: %s", ex)
        return None


def listen(config):
    servicebus_conn_str = config.azure.connection_string
    queue_name = config.azure.taskqueue

    last_message = dt.datetime.utcnow()
    diff = 0

    with ServiceBusClient.from_connection_string(servicebus_conn_str) as sb_client:
        receiver = sb_client.get_queue_receiver(queue_name=queue_name, max_wait_time=300)
        with receiver:
            logger.info("Listening on ServiceBus queue '%s'", queue_name)
            while diff < (60 * 15):
                batch = receiver.receive_messages(max_message_count=1, max_wait_time=5)
                found = False
                for message in batch:
                    found = True
                    last_message = dt.datetime.utcnow()
                    logger.info("Received message from %s", queue_name)
                    definiton = extract_defintion(message.body)
                    if definiton:
                        url, _, _ = (
                            definiton.get("request", {}).get("url", "").partition("?")
                        )
                        logger.info("Request received for %s", url)
                        handle_request(
                            config,
                            definiton,
                            complete_cb=message.complete  # This is not callable in v7.x
                        )
                    try:
                        receiver.complete_message(message)
                    except Exception as ex:
                        logger.error("Failed to complete message: %s", ex)
                if not found:
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
