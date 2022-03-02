from __future__ import print_function
import logging
import io
import os
import sys

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

DEFAULT_SETTINGS_FILE = [
    "/etc/apimetrics_agent",
    os.path.expanduser("~/.apimetrics_agent"),
    "apimetrics_agent.ini",
]


def _get_config(config, section, attr, fallback):
    return config.get(section, attr, fallback=fallback)


def _safe_get_config(config, section, attr, fallback):
    try:
        return config.get(section, attr)
    except configparser.NoOptionError:
        return fallback


class AzureConfig(object):
    def __init__(self):
        self.taskqueue = None
        self.connection_string = None


class Config(object):

    DEFAULT_HOST = "https://client.apimetrics.io"
    DEFAULT_CONFIG = """
[APImetrics]
apimetrics_taskqueue_name = development
apimetrics_display_name = Configuration Missing
apimetrics_user = nick
apimetrics_access_token = access_token
apimetrics_host_url = https://client.apimetrics.io

[SSL]
cert_file =
key_file =

[ServiceBus]
access_key_name =
access_key_value =
        """

    def __init__(self):
        self._config = None
        self._config_file = None
        self.access_token = None
        self.host_url = None

        self.proxy_host = None
        self.proxy_port = 0
        self.proxy_scheme = None

        self.ssl_cert_file = None
        self.ssl_key_file = None

        if sys.version_info[0] < 3:
            self.get_config = _safe_get_config
        else:
            self.get_config = _get_config

        self.name = None
        self.user = None
        self.display_name = None
        self.azure = AzureConfig()

    @property
    def proxies(self):
        if self.proxy_url:
            return {"http": self.proxy_url, "https": self.proxy_url}
        return None

    @property
    def proxy_url(self):
        if self.proxy_host:
            return "{scheme}://{host}:{port}".format(
                scheme=self.proxy_scheme, host=self.proxy_host, port=self.proxy_port
            )
        return None

    def load_from_file(self, config_file=None):

        self._config_file = config_file or DEFAULT_SETTINGS_FILE

        config = configparser.ConfigParser(allow_no_value=True)
        if sys.version_info[0] >= 3:
            config.read_file(io.StringIO(self.DEFAULT_CONFIG))
        else:
            config.read_file(io.BytesIO(self.DEFAULT_CONFIG))
        success_files = config.read(self._config_file)

        if success_files:
            self._config_file = success_files[-1]
        else:
            raise Exception("Unable to find any config files to open!")

        self.access_token = config.get("APImetrics", "apimetrics_access_token")
        self.host_url = (
            config.get("APImetrics", "apimetrics_host_url") or self.DEFAULT_HOST
        )

        self.name = config.get("APImetrics", "apimetrics_taskqueue_name")
        self.user = config.get("APImetrics", "apimetrics_user")
        self.display_name = config.get("APImetrics", "apimetrics_display_name")

        self.azure.taskqueue = config.get("APImetrics", "apimetrics_taskqueue_name")
        self.azure.connection_string = config.get("ServiceBus", "connection_string")

        if config.has_section("Proxy"):
            self.proxy_host = self.get_config(config, "Proxy", "host", fallback=None)
            self.proxy_port = self.get_config(config, "Proxy", "port", fallback=0)
            self.proxy_scheme = self.get_config(
                config, "Proxy", "scheme", fallback="http"
            )

        logger.info(
            "APImetrics Agent: %s [%s]", self.display_name, self.azure.taskqueue
        )
        logger.debug(
            "Service Bus Conn Str: %s", self.azure.connection_string,
        )

        # SSL config used for outgoing API Calls, not calls to APImetrics Host
        if config.has_section("SSL"):
            self.ssl_cert_file = self.get_config(
                config, "SSL", "cert_file", fallback=None
            )
            self.ssl_key_file = self.get_config(
                config, "SSL", "key_file", fallback=None
            )

        self._config = config

    def update(self, args):

        changes = False

        apimetrics_settings = (
            "taskqueue_name",
            "display_name",
            "user",
            "access_token",
            "host_url",
        )
        ssl_settings = ("ssl_cert_file", "ssl_key_file")
        servicebus_settings = ("key_name", "key_value")

        for arg in apimetrics_settings:
            if args[arg]:
                self._config.set("APImetrics", "APIMETRICS_%s" % arg, args[arg])
                changes = True

        for arg in servicebus_settings:
            if args[arg]:
                self._config.set("ServiceBus", "ACCESS_%s" % arg, args[arg])
                changes = True

        for arg in ssl_settings:
            if args[arg]:
                self._config.set("SSL", arg[4:].upper(), args[arg])
                changes = True

        if changes:
            with open(self._config_file, "w") as configfile:
                self._config.write(configfile)
            print("Saving {}".format(self._config_file))
            return False

        elif not args["show_settings"]:
            return True

        for arg in apimetrics_settings:
            print(
                "{}: {}".format(
                    arg, self._config.get("APImetrics", "APIMETRICS_%s" % arg)
                )
            )

        for arg in servicebus_settings:
            print(
                "{}: {}".format(arg, self._config.get("ServiceBus", "ACCESS_%s" % arg))
            )

        return False
