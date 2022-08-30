# pylint: disable=W0703
from __future__ import print_function
import logging
import os

VERSION = "0.12.4"

# Initialize logger
logger = logging.getLogger(__name__)  # pylint: disable=invalid-name
logging.getLogger("uamqp").setLevel(
    os.environ.get("DEBUG_LEVEL_URLLIB") or logging.WARNING
)
logger.addHandler(logging.NullHandler())

# import azure
# azure.http.httpclient.DEBUG_REQUESTS = True
# azure.http.httpclient.DEBUG_RESPONSES = True
