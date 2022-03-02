import logging
import requests
from . import VERSION

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name


def _register_agent_with_gae(config):
    logger.info(
        "Registering Agent %s - %s to owner %s",
        config.name,
        config.display_name,
        config.user,
    )

    url = "{}/remote-api/1/agent/register".format(config.host_url)
    data = {
        "name": config.name,
        "display_name": config.display_name,
        "owner": config.user,
        "access_token": config.access_token,
        "version": VERSION,
    }

    logger.info("Calling %s %s %s proxy: %s", "POST", url, repr(data), config.proxies)
    return requests.post(url, json=data, proxies=config.proxies, verify=False)


def register_agent_with_gae(config):
    logger.debug(
        "Register: %s %s %s %s %s",
        config.name,
        config.display_name,
        config.user,
        config.access_token,
        config.host_url,
    )

    try:
        response = _register_agent_with_gae(config)
        logger.info(
            "Register returned %d %s: %s",
            response.status_code,
            response.reason,
            response.text,
        )
    except Exception as ex:
        logger.error("Registration failed: %s", ex)
        raise

    if response.status_code != 200:
        error = response.content
        try:
            error = response.json()["error_msg"]
        except:  # pylint: disable=W0702
            pass
        raise Exception("Unable to register client with APImetrics: {}".format(error))
