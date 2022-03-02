import logging
import base64
import datetime as dt
import http.cookies
import ipaddress
import os
import time
import socket
import uuid
from urllib.parse import urlparse, urlunparse
from google.cloud import storage
from pycurl import error as pycurl_error
from apimetrics_agent import VERSION
from .pycurl_wrapper import request
from .pycurl_wrapper import (
    CurlError,
    InterfaceError,
    InvalidMethod,
    AuthError,
    PYCURL_AGENT_ERRORS,
    PYCURL_SETUP_ERRORS,
    PYCURL_ERROR_LOOKUP,
)
from .pycurl_wrapper import PYCURL_VERSION as requests_version

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

REDIRECTS = [301, 302, 303, 304]


class DomainResolveError(Exception):
    def __init__(self, text, underlying, *args: object) -> None:
        super().__init__(*args)
        self.text = text
        self.underlying = underlying


class CallTooLate(Exception):
    def __init__(self, date_limit, *args: object) -> None:
        super().__init__(*args)
        self.date_limit = date_limit


def get_normalized_http_url(url, prev_url):
    """Parses the URL and rebuilds it to be scheme://host/path;params?query."""
    parts = urlparse(url)
    prev_parts = urlparse(prev_url)

    scheme = parts.scheme or prev_parts.scheme
    host = parts.hostname or prev_parts.hostname
    port = parts.port or prev_parts.port

    host_port = host
    if (scheme == "https" and port is not None and port != 443) or (
        scheme == "http" and port is not None and port != 80
    ):
        host_port = "{}:{}".format(host, port)

    return urlunparse(
        (
            parts.scheme or prev_parts.scheme,
            host_port,
            parts.path,
            parts.params,
            parts.query,
            parts.fragment,
        )
    )


def check_for_connection_issues():
    should_retry = True
    try:
        request(
            "GET",
            "http://www.bing.com/",
            headers=[("Accept", "text/html")],
            timeout=120.0,
        )
    except CurlError as ex:
        logger.info(ex)
        should_retry = False
    return should_retry


def make_api_call(
    definition, messages, cert_file=None, key_file=None, domain_lookup_info=None
):

    method = definition["method"]
    url = definition["url"]
    body = definition["payload"] if "payload" in definition else None
    headers = definition["headers"] or {}

    parts = urlparse(url)

    # do the actual call
    if "User-Agent" not in headers:
        headers["User-Agent"] = "APImetrics/{} {}".format(VERSION, requests_version)

    # If this is set, the token will expire... do not make the API call if the token
    # has just expired in the last hour
    do_not_call_after = definition.get("do_not_call_after")
    if do_not_call_after:
        do_not_call_after_dt = dt.datetime.strptime(
            do_not_call_after, "%Y-%m-%dT%H:%M:%S.%f"
        )
        time_delta = dt.datetime.utcnow() - do_not_call_after_dt
        if time_delta > dt.timedelta(seconds=0) and time_delta < dt.timedelta(hours=1):
            minutes = int(time_delta.total_seconds() / 60)
            messages.append("Token expired ~{} minutes ago".format(minutes))
            raise CallTooLate(do_not_call_after_dt)
        elif time_delta > dt.timedelta(seconds=0):
            messages.append("Token expired over an hour ago, continuing anyway")

    timeout=120.0
    tags = definition.get('tags', [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith('apimetrics:timeout:'):
            try:
                timeout = float(tag.replace('apimetrics:timeout:', ''))
                if timeout >= 120.0 or timeout <= 0.0:
                    timeout = 120.0
            except (ValueError, TypeError):
                pass

    resp = None
    for _ in range(3):
        logger.info("Calling %s %s to %s", method, parts.path, parts.hostname)
        messages.append("Calling {} {}".format(method, parts.path))
        try:
            resp = request(
                method,
                url,
                data=body,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                cert_file=cert_file,
                key_file=key_file,
                domain_lookup_info=domain_lookup_info,
            )
            break
        except CurlError:  # ConnectionError?
            logger.debug("Checking for connection issue...")
            messages.append("Checking for connection issue...")
            if check_for_connection_issues():
                # Problem is not our fault
                logger.debug("... no problem found")
                messages.append("... no problem found.")
                raise
            else:
                messages.append("... there may have been a problem, will retry.")
    return resp


class APIhandler(object):
    def __init__(self, definition):
        self._definition = definition
        self._cert_file = definition.get("_cert_file")
        self._key_file = definition.get("_key_file")
        self._result = definition.copy()
        self._result["start_time"] = None
        self._result["end_time"] = None
        self._result["response"] = None
        self._result["messages"] = []
        self.follow_redirects = not ("apimetrics:noredirect" in definition['request'].get('tags', []))

    @property
    def result(self):
        return self._result

    def make_api_call_with_redirects(self):
        request = self._definition['request']
        messages = self._result["messages"]
        tags = request.get("tags", [])

        # Only do this once
        if request.get("isPayloadBinary", False) and "payload" in request:
            body = request["payload"]
            try:
                byts = bytes(body, "utf-8")
                request["payload"] = base64.b64decode(byts)
            except Exception as ex:  # pylint: disable=W0703
                logger.warning(ex)

        domain_lookup_info = None

        no_local_check = 'apimetrics:no_local_check' in tags

        for _ in range(10):

            if domain_lookup_info is None:
                domain_lookup_info = self.lookup_dns(request["url"], messages, no_local_check)
            resp = make_api_call(
                request,
                messages,
                self._cert_file,
                self._key_file,
                domain_lookup_info,
            )

            if resp is None:
                return resp

            messages.append(
                "Got response HTTP {} {}".format(resp.status_code, resp.reason)
            )
            if not self.follow_redirects or resp.status_code not in REDIRECTS:
                break

            # Store response and handle cookie
            new_location = None
            cookie = http.cookies.SimpleCookie()

            for key, val in resp.request.headers:
                if key.lower() == "cookie":
                    cookie.load(str(val))

            for key, val in resp.headers:

                if key.lower() == "location":
                    new_location = val

                if key.lower() == "set-cookie":
                    cookie.load(str(val))

            cookie_str = "; ".join(
                ["%s=%s" % (i, cookie[i].coded_value) for i in cookie]
            )

            if not new_location:
                break

            prev_url = request["url"]

            logging.info("Redirect to %s", new_location.split("?")[0])
            # self.messages.append('Redirect to %s' % resp.headers['Location'].split('?')[0])
            request["url"] = get_normalized_http_url(new_location, prev_url)
            domain_lookup_info = None  # reset domain info

            messages.append("Redirecting to {}".format(request["url"]))

            if cookie_str:
                keys_to_remove = []
                for key in request["headers"].keys():
                    if key.lower() == "cookie":
                        keys_to_remove.append(key)
                for key in keys_to_remove:
                    del request["headers"][key]

                request["headers"]["Cookie"] = cookie_str

            # Browsers do this
            if request["method"] in ["POST", "PUT"]:
                request["method"] = "GET"
                request["payload"] = None

        return resp

    def do_dns_lookup(self, domain, port):
        lookup_ex = None
        start_time = time.time()
        try:
            address_list = socket.getaddrinfo(
                domain, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP
            )
        except Exception as ex:  # pylint: disable=broad-except
            address_list = None
            lookup_ex = ex
        end_time = time.time()
        lookup_time = end_time - start_time

        if not address_list:
            return None, lookup_time, lookup_ex

        # address_info = random.choice(address_list)
        address_info = address_list[0]

        sockaddr = address_info[4]
        ip_addr, _ = sockaddr

        return ip_addr, lookup_time, lookup_ex

    def lookup_dns(self, url, messages, no_local_check):
        parts = urlparse(url)
        # Can contain port
        domain, _, port = parts.netloc.lower().partition(":")
        if not port:
            port = 443 if parts.scheme == "https" else 80

        need_lookup = True
        try:
            ip_check = ipaddress.ip_address(domain)
            if not isinstance(ip_check, ipaddress.IPv4Address):
                raise DomainResolveError(
                    "Requested IP address ({}) is not an IPv4 address".format(domain),
                    None,
                )
            # The API defined the IP address in the URL, and it is an IPv4 address, carry on
            ip_addr = domain
            lookup_time = 0
            lookup_ex = None
            need_lookup = False

        except ValueError:
            # Domain name is not an IPv4 address as expected, so do lookup
            ip_addr, lookup_time, lookup_ex = self.do_dns_lookup(domain, port)
            if not ip_addr:
                raise DomainResolveError(
                    "Did not resolve any IPv4 addresses for domain {}".format(domain),
                    lookup_ex,
                )
            messages.append("Domain name {} resolved to {}".format(domain, ip_addr))

        ipv4 = ipaddress.IPv4Address(ip_addr)
        if not ipv4.is_global and not no_local_check:
            raise DomainResolveError(
                "Resolved IP address ({}) is not a public IP address".format(ip_addr),
                None,
            )

        # Save timing info
        self._result["dns_lookups"] = self._result.get("dns_lookups", []) + [
            (domain, ip_addr, lookup_time)
        ]

        if need_lookup:
            return (domain, port, ip_addr)

        return None

    def run(self):
        logger.debug("make_request")

        response = None
        data = None
        exception_str = None
        exception_str2 = None
        error_type = None

        definition = self._definition["request"]

        self._result["start_time"] = dt.datetime.utcnow().isoformat()
        try:
            response = self.make_api_call_with_redirects()
            if response is None:
                error_type = "agent"
                exception_str = "Unknown connection error"
                logger.warning("Agent connection issue")
            else:
                data = response.content

        except CallTooLate as ex:
            error_type = "skipped"
            exception_str = "API call was skipped because the token had expired"
            exception_str2 = "Token expired at: {} UTC".format(
                ex.date_limit.isoformat()
            )

        except DomainResolveError as ex:
            error_type = "download"
            exception_str = "A problem while resolving domain name"
            exception_str2 = ex.text
            logger.warning("Excepted in call_api: %s", exception_str)

        except InterfaceError as ex:
            error_type = "agent"
            exception_str = "A error before making the call."
            exception_str2 = repr(ex)
            logger.warning("Excepted in call_api: %s", exception_str)

        except InvalidMethod as ex:
            error_type = "api_setup"
            exception_str = "A valid method is required to make a request."
            exception_str2 = repr(ex)
            logger.warning("Excepted in call_api: %s", exception_str)

        except CurlError as ex:
            error_type = "download"
            if ex.code in PYCURL_AGENT_ERRORS:
                error_type = "agent"
            elif ex.code in PYCURL_SETUP_ERRORS:
                error_type = "api_setup"
            exception_str = PYCURL_ERROR_LOOKUP.get(ex.code, "Unknown error")
            exception_str2 = str(ex)
            logger.warning("Excepted in call_api: %s %s", exception_str, exception_str2)
            response = ex.response

        except AuthError as ex:
            error_type = "download"
            exception_str = "Problem making the call."
            exception_str2 = repr(ex)
            logger.warning("Excepted in call_api: %s", exception_str)

        except pycurl_error as ex:
            error_type = "download"
            exception_str = "Problem making the call."
            exception_str2 = str(ex)
            logger.warning("Excepted in call_api: %s", ex)

        except AssertionError as ex:
            error_type = "agent"
            exception_str = "Problem making the call."
            exception_str2 = str(ex)
            logger.warning("Excepted in call_api: %s", ex)

        self._result["end_time"] = dt.datetime.utcnow().isoformat()

        # self._result['request'] = request
        # self._result['response'] = None
        self._result["exception"] = exception_str
        self._result["exception_debug"] = exception_str2
        self._result["exception_type"] = error_type

        if response is not None and response.request:
            if response.status_code >= 200 and response.status_code < 300:
                logger.info("Got response %d %s", response.status_code, response.reason)
            else:
                logger.warning(
                    "Got response %d %s", response.status_code, response.reason
                )
            if data:
                logger.debug("Data len %d", len(data))

            self._result["response"] = {
                "url": response.request.url,
                "method": response.request.method,
                "headers": response.headers,  # was dict(...)
                "payload": data,
                "status_code": response.status_code,
                "status_string": response.reason,
            }

        # Pass real values back to service so we can handle cookies
        if response and response.request:
            self._result["request"]["url"] = response.request.url
            self._result["request"]["method"] = response.request.method
            if response.request.headers:
                self._result["request"][
                    "headers"
                ] = response.request.headers  # was dict(...)

            # This is a work-around so we can handle cookies even if we get re-directed to a
            # URL that doesn't use the cookie (i.e. has it's path set to something else)
            if "Cookie" not in self._result["request"]["headers"]:
                for prev_resp_headers in response.headers_history:
                    if "Set-Cookie" in dict(prev_resp_headers[1:]):
                        # self._result['response']['headers']['Set-Cookie'] =
                        #     prev_resp.headers['Set-Cookie']
                        self._result["response"]["headers"].append(
                            ("Set-Cookie", dict(prev_resp_headers[1:])["Set-Cookie"])
                        )

            # pylint: disable=W0212
            if response._response_info:
                self._result["curl_info"] = response._response_info

        if self._result["request"].get("isPayloadBinary", None):
            self._result["request"]["payload"] = "<< BINARY DATA >>"

        upload_response_content = False

        if self._result["response"]:
            if data:
                if len(data) < 32000:
                    try:
                        self._result["response"]["payload"] = self._result["response"][
                            "payload"
                        ].decode("utf-8")
                    except Exception as ex:  # pylint: disable=W0703
                        self._result["response"]["payload"] = "<< BINARY DATA >>"
                        self._result["messages"] = [str(ex)]
                        logger.debug("Binary Data - try upload")
                        upload_response_content = True
                else:
                    logger.debug("Large Data - try upload")
                    self._result["response"]["payload"] = "<< LARGE DATA >>"
                    upload_response_content = True
            else:
                self._result["response"]["payload"] = None  # Handle b''response

        if upload_response_content:
            # Generate random GUID
            guid = str(uuid.uuid4())
            # Upload content
            content_type = dict(response.headers).get(
                "Content-Type", "application/octet-stream"
            )
            logger.debug(
                "Attempting upload of data - type %s - guid %s", content_type, guid
            )
            # Env variable GOOGLE_APPLICATION_CREDENTIALS should be set
            client = storage.Client()  # project='apimetrics-qc')
            bucket = client.get_bucket(
                os.getenv("APIM_RESPONSE_BUCKET", "live-responses")
            )
            blob = bucket.blob(guid)
            blob.upload_from_string(data, content_type=content_type)
            self._result["response"]["payload_id"] = guid
            logger.debug(
                "Upload of data - type %s - guid %s complete", content_type, guid
            )

        logger.debug("make_request complete")
        return self._result


def handle_api_request(definition):
    handler = APIhandler(definition)
    handler.run()
    return handler.result
