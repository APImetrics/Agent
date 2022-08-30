import logging
import os
from datetime import datetime
import tempfile
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from apimetrics_agent import VERSION
from .controller import handle_api_request

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


class APImetricsThread(object):
    def __init__(self, config):
        self.config = config

    def handle_definition(self, definition, complete_cb):
        logger.debug("handle_definition")

        # exception_str = None
        result = None
        if not definition:
            logger.error("definition not set")
            complete_cb()
            return

        test_key_str = self.validate_data(definition)
        if not test_key_str:
            logger.error("Invalid request data: %s", definition)
            complete_cb()
            return

        cert_file_name = None
        key_file_name = None
        if definition["request"].get("ssl_cert"):
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as cert:
                cert.write(definition["request"]["ssl_cert"])
                definition["_cert_file"] = cert.name
                cert_file_name = cert.name
                logger.debug("Using cert file %s", cert_file_name)
            del definition["request"]["ssl_cert"]

            if definition["request"].get("ssl_key"):
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as cert:
                    cert.write(definition["request"]["ssl_key"])
                    definition["_key_file"] = cert.name
                    key_file_name = cert.name
                del definition["request"]["ssl_key"]

        elif self.config.ssl_cert_file:
            definition["_cert_file"] = self.config.ssl_cert_file
            definition["_key_file"] = self.config.ssl_key_file

        try:
            complete_cb()
            result = handle_api_request(definition)
        except Exception as ex:  # pylint: disable=W0703
            logger.error("Exception in handle_api_request %s", ex)
            result = {
                "test_key_str": test_key_str,
                "result_key_str": definition["result_key_str"],
                "start_time": datetime.utcnow().isoformat(),
                "request": definition["request"],
                "response": None,
                "exception": "Problem with test agent: {}".format(repr(ex)),
            }

        if definition.get("expected_trigger_time"):
            result["expected_trigger_time"] = definition["expected_trigger_time"]
        if definition.get("trigger_time"):
            result["trigger_time"] = definition["trigger_time"]

        if cert_file_name:
            try:
                os.remove(cert_file_name)
            except FileNotFoundError:
                pass
        if key_file_name:
            try:
                os.remove(key_file_name)
            except FileNotFoundError:
                pass

        res = self.send_result_to_gae(result, test_key_str)
        if res:
            logger.info("Got response %d %s", res.status_code, res.reason)
        else:
            logger.warning("No response for send_result_to_gae")
        # logger.debug(res.data) #read(decode_content=True))

    def validate_data(self, output):
        logger.debug("validate_data")
        if (
            "access_token" in output
            and self.config.access_token == output["access_token"]
        ):
            return output["test_key_str"]
        return None

    def send_result_to_gae(self, result, test_key_str):
        logger.debug("send_result_to_gae")
        url = "{}/remote-api/1/test/{}/".format(self.config.host_url, test_key_str)
        result["version"] = VERSION

        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.5,
            method_whitelist=["POST"],
            status_forcelist=[429, 500, 501, 502, 503, 504],
        )
        session.mount(self.config.host_url, HTTPAdapter(max_retries=retries))

        logger.info("Calling %s %s proxy: %s", "POST", url, self.config.proxies)
        return session.post(url, json=result, proxies=self.config.proxies, verify=False)


def handle_request(config, definition, complete_cb=None):
    logger.debug("handle_request")
    thread = APImetricsThread(config)
    thread.handle_definition(definition, complete_cb)
