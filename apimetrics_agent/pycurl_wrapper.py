# pylint: disable=too-many-lines
"""
 This is a cut-down version of human_curl https://github.com/Lispython/human_curl/ which is
 not currently Python 3 compatible.
 It should be a "requests"-like wrapper of PyCurl.
"""
from __future__ import print_function
import logging
from http.client import responses
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl
from urllib.parse import urlencode, quote_plus
from re import compile as re_compile

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO
import json
import os
import collections

import pycurl

logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

logging.getLogger("pycurl").setLevel(os.environ.get("DEBUG_LEVEL") or logging.INFO)
DEBUG_MODE = bool(os.environ.get("DEBUG_LEVEL") == "DEBUG")

PYCURL_VERSION = pycurl.version

DEFAULT_TIME_OUT = 15.0
STATUSES_WITH_LOCATION = (301, 302, 303, 305, 307)
PYCURL_VERSION_INFO = pycurl.version_info()
HTTP_GENERAL_RESPONSE_HEADER = re_compile(
    r"(?P<version>HTTP\/.*?)\s+(?P<code>\d{3})\s+(?P<message>.*)"
)

# FULL LIST OF GETINFO OPTIONS
CURL_INFO_MAP = {
    # timers
    # An overview of the six time values available from curl_easy_getinfo()
    # perform() --> NAMELOOKUP --> CONNECT --> APPCONNECT
    # --> PRETRANSFER --> STARTTRANSFER --> TOTAL --> REDIRECT
    "TOTAL_TIME": pycurl.TOTAL_TIME,
    "NAMELOOKUP_TIME": pycurl.NAMELOOKUP_TIME,
    "CONNECT_TIME": pycurl.CONNECT_TIME,
    "APPCONNECT_TIME": pycurl.APPCONNECT_TIME,
    "PRETRANSFER_TIME": pycurl.PRETRANSFER_TIME,
    "STARTTRANSFER_TIME": pycurl.STARTTRANSFER_TIME,
    "REDIRECT_TIME": pycurl.REDIRECT_TIME,
    "HTTP_CODE": pycurl.HTTP_CODE,
    "REDIRECT_COUNT": pycurl.REDIRECT_COUNT,
    "REDIRECT_URL": pycurl.REDIRECT_URL,
    "SIZE_UPLOAD": pycurl.SIZE_UPLOAD,
    "SIZE_DOWNLOAD": pycurl.SIZE_DOWNLOAD,
    "SPEED_DOWNLOAD": pycurl.SPEED_DOWNLOAD,
    "SPEED_UPLOAD": pycurl.SPEED_UPLOAD,
    "HEADER_SIZE": pycurl.HEADER_SIZE,
    "REQUEST_SIZE": pycurl.REQUEST_SIZE,
    "SSL_VERIFYRESULT": pycurl.SSL_VERIFYRESULT,
    "SSL_ENGINES": pycurl.SSL_ENGINES,
    "CONTENT_LENGTH_DOWNLOAD": pycurl.CONTENT_LENGTH_DOWNLOAD,
    "CONTENT_LENGTH_UPLOAD": pycurl.CONTENT_LENGTH_UPLOAD,
    "CONTENT_TYPE": pycurl.CONTENT_TYPE,
    "HTTPAUTH_AVAIL": pycurl.HTTPAUTH_AVAIL,
    "PROXYAUTH_AVAIL": pycurl.PROXYAUTH_AVAIL,
    "OS_ERRNO": pycurl.OS_ERRNO,
    "NUM_CONNECTS": pycurl.NUM_CONNECTS,
    "PRIMARY_IP": pycurl.PRIMARY_IP,
    "CURLINFO_LASTSOCKET": pycurl.LASTSOCKET,
    "EFFECTIVE_URL": pycurl.EFFECTIVE_URL,
    "INFO_COOKIELIST": pycurl.INFO_COOKIELIST,
    "RESPONSE_CODE": pycurl.RESPONSE_CODE,
    "HTTP_CONNECTCODE": pycurl.HTTP_CONNECTCODE,
    # "FILETIME": pycurl.FILETIME
    # "PRIVATE": pycurl.PRIVATE, # (Added in 7.10.3)
    # "CERTINFO": pycurl.CERTINFO,
    "PRIMARY_PORT": pycurl.PRIMARY_PORT,
    "LOCAL_IP": pycurl.LOCAL_IP,
    "LOCAL_PORT": pycurl.LOCAL_PORT,
}


class HTTPError(Exception):
    """Exception for failed HTTP request
    :param code: HTTP error integer error code, e. g. 404
    :param message: error message string
    """

    def __init__(self, code, message=None):
        self.code = code
        message = message or responses.get(code, "Unknown")
        Exception.__init__(self, "%d: %s" % (self.code, message))


class InvalidMethod(Exception):
    """Exception raise if `Request.__init__()` get unsupported method
    """


class CurlError(Exception):
    """Exception raise when `pycurl.Curl` raise connection errors
    :param code: HTTP error integer error code, e. g. 404
    :param message: error message string
    """

    def __init__(self, code, message=None, response=None):
        self.code = code
        self.response = response
        message = message or responses.get(code, "Unknown")
        Exception.__init__(self, message)


class InterfaceError(Exception):
    """Raises when get not allowed parametr type
    or not allowed parameter
    """


class AuthError(Exception):
    """Raised by auth manager
    """


def helper(dict_in):
    tmp = []
    for key, val in dict_in:
        if isinstance(val, (tuple, list)):
            for val2 in val:
                tmp.append((key, val2))
        else:
            tmp.append((key, val))
    return tmp


def data_wrapper(data):
    """Convert data to list and returns
    """
    # logger.debug('data_wrapper %s', data)
    if isinstance(data, dict):
        return helper(iter(data.items()))
    elif isinstance(data, (tuple, list)):
        return helper(data)
    elif data is None:
        return data
    else:
        raise InterfaceError(
            "%s argument must be list, tuple or dict, not %s "
            % ("data_wrapper", type(data))
        )


_TO_UNICODE_TYPES = (str, type(None))


def to_unicode(value):
    """Converts a string argument to a unicode string.
    If the argument is already a unicode string or None, it is returned
    unchanged.  Otherwise it must be a byte string and is decoded as utf8.
    """
    if isinstance(value, _TO_UNICODE_TYPES):
        return value
    assert isinstance(value, bytes)
    return value.decode("utf-8")


def urlnoencode(query):
    """Convert a sequence of two-element tuples or dictionary into a URL query string
    without url-encoding.
    """
    output = []
    arg = "%s=%s"

    if hasattr(query, "items"):
        # mapping objects
        query = list(query.items())

    for k, val in query:
        output.append(arg % (k, val))

    return "&".join(output)


class CaseInsensitiveDict(collections.MutableMapping):
    """A case-insensitive ``dict``-like object.
    Implements all methods and operations of
    ``collections.MutableMapping`` as well as dict's ``copy``. Also
    provides ``lower_items``.
    All keys are expected to be strings. The structure remembers the
    case of the last key to be set, and ``iter(instance)``,
    ``keys()``, ``items()``, ``iterkeys()``, and ``iteritems()``
    will contain case-sensitive keys. However, querying and contains
    testing is case insensitive::
        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True
    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header, regardless
    of how the header name was originally stored.
    If the constructor, ``.update``, or equality comparison
    operations are given keys that have equal ``.lower()``s, the
    behavior is undefined.
    """

    def __init__(self, data=None, **kwargs):
        self._store = collections.OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key, value):
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other):
        if isinstance(other, collections.Mapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self):
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self):
        return str(dict(self.items()))


class Request(object):
    r"""A single HTTP / HTTPS requests
    Usage:
    >>> request = Request("GET", "http://google.com")
    >>> print(repr(request))
    <Request: GET [ http://google.com ]>
    >>> request.send()
    >>> response = requests.response
    """

    SUPPORTED_METHODS = ("GET", "HEAD", "POST", "DELETE", "PUT", "OPTIONS", "PATCH")

    def __init__(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        timeout=None,
        connection_timeout=None,
        allow_redirects=True,
        max_redirects=10,
        encode_query=None,
        cert_file=None,
        key_file=None,
        validate_cert=False,
        domain_lookup_info=None,
    ):
        """A single HTTP / HTTPS request
        Arguments:
        - `url`: (string) resource url
        - `method`: (string) one of `self.SUPPORTED_METHODS`
        - `data`: (dict, duple, string) data to send as Content-Disposition form-data
        - `params`: (dict, tuple) of GET params (?param1=value1&param2=value2)
        - `headers`: (dict, tuple) of request headers
        - `cookies`: (dict, tuple or CookieJar) of cookies
        - `files`: (dict, tuple or list) of files
           Example:
               (('field_file_name', '/path/to/file.txt'),
               ('field_file_name', open('/path/to/file.txt')),
               ('multiple_files_field', (open("/path/to/file.1.txt"), open("/path/to/file.1.txt"))),
               ('multiple_files_field', ("/path/to/file.1.txt", "/path/to/file.1.txt")))
        - `timeout`: (float) connection time out
        - `connection_timeout`: (float)
        - `allow_redirects`: (bool) follow redirects parametr
        - `proxy`: (dict, tuple or list) of proxies
           Examples:
               ('http', ('127.0.0.1', 9050))
               ('http', ('127.0.0.1', 9050, ('username', 'password')))
        - `auth`: (dict, tuple or list) for resource base auth
        - `network_interface`: (str) Pepform an operation using a specified interface.
           You can enter interface name, IP address or host name.
        - `use_gzip`: (bool) accept gzipped data
        - `validate_cert`: (bool) validate server certificate
        - `ca_certs`: tells curl to use the specified certificate file to verify the peer.
        - `cert`: (string) tells curl to use the specified certificate file
           when getting a file with HTTPS.
        - `debug`: (bool) use for `pycurl.DEBUGFUNCTION`
        - `user_agent`: (string) user agent
        - `ip_v6`: (bool) use ipv6 protocol
        - `options`: (tuple, list) low level pycurl options using
        """
        self._url = url
        if not method or not isinstance(method, str):
            raise InterfaceError("method argument must be string")

        if method.upper() not in self.SUPPORTED_METHODS:
            raise InvalidMethod("cURL do not support %s method" % method.upper())

        self._method = method.upper()

        self._headers = data_wrapper(headers)
        ##logger.debug(self._headers)

        self._params = data_wrapper(params)

        # String, dict, tuple, list
        self._data = None
        if isinstance(data, str):
            self._data = str.encode(data)
        elif isinstance(data, bytes):
            self._data = data
        else:
            self._data = data_wrapper(data)

        # follow by location header field
        self._allow_redirects = allow_redirects
        self._max_redirects = max_redirects

        self._timeout = int(timeout or DEFAULT_TIME_OUT)
        self._connection_timeout = connection_timeout

        # Certificates
        self._validate_cert = validate_cert
        # self._ca_certs = ca_certs
        self._cert_file = cert_file
        self._key_file = key_file
        self.response = None

        # if options is None:
        #     self._options = None
        # elif isinstance(options, (list, tuple)):
        #     self._options = data_wrapper(options)
        # else:
        #     raise InterfaceError("options must be None, list or tuple")

        self._curl = None

        self.body_output = BytesIO()
        self.headers_output = BytesIO()

        self._encode_query = encode_query

        self._opener = None
        self.domain_lookup_info = domain_lookup_info

    def __repr__(self,):
        return "<%s: %s [ %s ]>" % (self.__class__.__name__, self._method, self._url)

    @property
    def url(self):
        if not self._url:
            self._url = self._build_url()
        return self._url

    def _build_url(self):
        """Build resource url
        Parsing ``self._url``, add ``self._params`` to query string if need
        :return self._url: resource url
        """
        scheme, netloc, path, params, query, fragment = urlparse(self._url)

        # IDN domains support
        # netloc = str(to_unicode(netloc).encode('idna'))

        if not netloc:
            raise InterfaceError("Invalid url")
        elif not scheme:
            scheme = "http"

        tmp = []
        if self._params is not None:
            for param, value in self._params:
                if isinstance(value, tuple):
                    for i in value:
                        tmp.append((param, i))
                elif isinstance(value, str):
                    tmp.append((param, value))

        if tmp:
            tmp = parse_qsl(query, keep_blank_values=True) + tmp
        else:
            try:
                tmp = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                tmp = query

        if isinstance(tmp, str):
            encode = quote_plus
            noencode = lambda result: result
        else:
            encode = urlencode
            noencode = urlnoencode

        if self._encode_query:
            query = encode(tmp)
        else:
            query = noencode(tmp)

        del tmp

        # logger.debug("scheme %s netloc %s path %s params %s query %s fragment %s", scheme,
        # netloc, path, params, query, fragment)
        self._url = urlunparse([scheme, netloc, path, params, query, fragment])

        logger.debug("_build_url returns %s", self._url)
        return self._url

    def send(self):
        """Send request to self._url resource
        :return: `Response` object
        """
        logger.debug("send")

        try:
            opener = self.build_opener(self._build_url())
            opener.perform()
            # if close before getinfo, raises pycurl.error can't invote getinfo()
            # opener.close()
        except pycurl.error as ex:
            try:
                self.response = self.make_response()
            except Exception as ex2:  # pylint: disable=broad-except
                logger.warning(repr(ex2))
            raise CurlError(*ex.args, response=self.response)

        self.response = self.make_response()
        return self.response

    def make_response(self):
        """Make response from finished opener
        :return response: :class:`Response` object
        """
        logger.debug("make_response")
        response = Response(
            url=self._url,
            curl_opener=self._opener,
            body_output=self.body_output,
            headers_output=self.headers_output,
            req=self,
        )
        # try:
        #     response.parse_cookies()
        # except Exception as ex:
        #     logger.error(ex, exc_info=True)
        return response

    def setup_writers(self, opener, headers_writer, body_writer):
        """Setup headers and body writers
        :param opener: :class:`pycurl.Curl` object
        :param headers_writer: `StringIO` object
        :param body_writer: `StringIO` object
        """
        # Body and header writers
        logger.debug("setup_writers")
        opener.setopt(pycurl.HEADERFUNCTION, headers_writer)
        opener.setopt(pycurl.WRITEFUNCTION, body_writer)

    @staticmethod
    def clean_opener(opener):
        """Reset opener options
        :param opener: :class:`pycurl.Curl` object
        :return opener: clean :`pycurl.Curl` object
        """
        logger.debug("clean_opener")
        opener.reset()
        return opener

    def debug_func(self, param1, param2):
        if param1 != 3:  # 3 is the payload
            logger.debug("%s %s", param1, param2)

    def build_opener(self, url, opener=None):
        """Compile pycurl.Curl instance
        Compile `pycurl.Curl` instance with given instance settings
        and return `pycurl.Curl` configured instance, StringIO instances
        of body_output and headers_output
        :param url: resource url
        :return: an ``(opener, body_output, headers_output)`` tuple.
        """
        # http://curl.haxx.se/mail/curlpython-2005-06/0004.html
        # http://curl.haxx.se/mail/lib-2010-03/0114.html

        logger.debug("build_opener")
        opener = opener or pycurl.Curl()

        if getattr(opener, "dirty", True):
            opener = self.clean_opener(opener)

        logger.debug("Open url: %s", url)
        opener.setopt(pycurl.URL, url)
        opener.setopt(pycurl.NOSIGNAL, 1)
        opener.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)

        if self.domain_lookup_info:
            (host, port, ip_addr) = self.domain_lookup_info
            domain_info = "{}:{}:{}".format(host, port, ip_addr)
            logger.debug(domain_info)
            opener.setopt(pycurl.RESOLVE, [domain_info.encode('utf-8')])

        opener.unsetopt(pycurl.USERPWD)

        if self._headers:
            # heads = ["%s: %s" % ((f, "-"), v) for f, v in
            # CaseInsensitiveDict(self._headers).items()]
            heads = [
                "%s: %s" % (f, v) for f, v in CaseInsensitiveDict(self._headers).items()
            ]
            # logger.debug("Set headers %s", "\r\n".join(heads))
            opener.setopt(pycurl.HTTPHEADER, heads)

        # Option -L  Follow  "Location: "  hints
        if self._allow_redirects is True:
            # logger.debug("Allow redirects")
            opener.setopt(pycurl.FOLLOWLOCATION, self._allow_redirects)
            if self._max_redirects:
                opener.setopt(pycurl.MAXREDIRS, self._max_redirects)

        # Set timeout for a retrieving an object
        if self._timeout is not None:
            # logger.debug("Set timeout: %s", self._timeout)
            opener.setopt(pycurl.TIMEOUT, self._timeout)
        if self._connection_timeout is not None:
            # logger.debug("Set connect timeout: %s", self._timeout)
            opener.setopt(pycurl.CONNECTTIMEOUT, self._connection_timeout)

        # Setup debug output write function
        opener.setopt(pycurl.VERBOSE, 0)
        if DEBUG_MODE:
            opener.setopt(pycurl.VERBOSE, 1)
            opener.setopt(pycurl.DEBUGFUNCTION, self.debug_func)

        # logger.debug("Setup user agent %s", self.user_agent)
        # opener.setopt(pycurl.USERAGENT, self.user_agent)

        if self._validate_cert not in (None, False):
            logger.debug("Validate certificate")
            # Verify that we've got the right site; harmless on a non-SSL connect.
            opener.setopt(pycurl.SSL_VERIFYPEER, 1)
            opener.setopt(pycurl.SSL_VERIFYHOST, 2)
        else:
            opener.setopt(pycurl.SSL_VERIFYPEER, 0)
            opener.setopt(pycurl.SSL_VERIFYHOST, 0)

        ## (HTTPS) Tells curl to use the specified certificate file when getting a
        ## file with HTTPS. The certificate must be in PEM format.
        ## If the optional password isn't specified, it will be queried for on the terminal.
        ## Note that this certificate is the private key and the private certificate concatenated!
        ## If this option is used several times, the last one will be used.
        if self._cert_file:
            opener.setopt(pycurl.SSLCERTTYPE, "PEM")
            opener.setopt(pycurl.SSLCERT, self._cert_file)
            if self._key_file:
                opener.setopt(pycurl.SSLKEY, self._key_file)

        # set empty cookie to activate cURL cookies
        opener.setopt(pycurl.COOKIELIST, "")

        curl_options = {
            "GET": pycurl.HTTPGET,
            "POST": pycurl.POST,
            # "PUT": pycurl.UPLOAD,
            "PUT": pycurl.PUT,
            "HEAD": pycurl.NOBODY,
        }

        logger.debug("Use method %s for request", self._method)
        if self._method in list(curl_options.values()):
            opener.setopt(curl_options[self._method], True)
        elif self._method in self.SUPPORTED_METHODS:
            opener.setopt(pycurl.CUSTOMREQUEST, self._method)
        else:
            raise InvalidMethod("cURL request do not support %s" % self._method)

        # Responses without body
        if self._method in ("OPTIONS", "HEAD", "DELETE"):
            opener.setopt(pycurl.NOBODY, True)

        if self._method in ("POST", "PUT", "PATCH"):
            # if isinstance(self._data, str):
            #     logger.debug(("self._data is string"))
            # logger.debug(("self._data", self._data))
            request_buffer = BytesIO(self._data)

            # raw data for body request
            opener.setopt(pycurl.READFUNCTION, request_buffer.read)

            def ioctl(cmd):
                # logger.debug(("cmd", cmd))
                if cmd == pycurl.IOCMD_RESTARTREAD:
                    request_buffer.seek(0)

            opener.setopt(pycurl.IOCTLFUNCTION, ioctl)
            if self._method == "PUT":
                opener.setopt(pycurl.PUT, True)
                opener.setopt(pycurl.INFILESIZE, len(self._data))
            else:
                opener.setopt(pycurl.POST, True)
                opener.setopt(pycurl.POSTFIELDSIZE, len(self._data))

            # elif isinstance(self._data, (tuple, list, dict)):
            #     headers = dict(self._headers or [])
            #     if 'multipart' in headers.get('Content-Type', ''):
            #         # use multipart/form-data;
            #         opener.setopt(opener.HTTPPOST, data_wrapper(self._data))
            #     else:
            #         # use postfields to send vars as application/x-www-form-urlencoded
            #         encoded_data = urlencode(self._data, doseq=True)
            #         opener.setopt(pycurl.POSTFIELDS, encoded_data)

        # if isinstance(self._options, (tuple, list)):
        #     for key, value in self._options:
        #         opener.setopt(key, value)

        self.body_output = BytesIO()
        self.headers_output = BytesIO()

        self.setup_writers(opener, self.headers_output.write, self.body_output.write)

        self._opener = opener

        return opener

    @property
    def method(self):
        return self._method

    @property
    def headers(self):
        return self._headers


class Response(object):
    """Response object
    """

    def __init__(self, url, curl_opener, body_output, headers_output, req=None):
        """
        Arguments:
        :param url: resource url
        :param curl_opener: :class:`pycurl.Curl` object
        :param body_output: :StringIO instance
        :param headers_output: :StringIO instance
        :param request: :class:`Request` instance
        """

        logger.debug("Reponse.__init__ %s", url)

        # Requested url
        self._request_url = url
        self._url = None

        # Request object
        self._request = req

        # Response headers
        self._headers = None

        # Seconds from request start to finish
        self.request_time = None
        self._curl_opener = curl_opener

        # StringIO object for response body
        self._body_otput = body_output
        # StringIO object for response headers
        self._headers_output = headers_output

        # :Response status code
        self._status_code = None
        self._reason = None

        # Unziped end decoded response body
        self._content = None

        # Redirects history
        self._history = []

        # list of parsed headers blocks
        self._headers_history = []

        # get data from curl_opener.getinfo before curl_opener.close()
        self._response_info = dict()
        self._get_curl_info()

        # not good call methods in __init__
        # it's really very BAD
        # DO NOT UNCOMMENT
        # self._parse_headers_raw()

    def __repr__(self):
        return "<%s: %s >" % (self.__class__.__name__, self.status_code)

    def _get_curl_info(self):
        """Extract info from `self._curl_opener` with getinfo()
        """
        logger.debug("Reponse._get_curl_info")
        for field, value in CURL_INFO_MAP.items():
            try:
                field_data = self._curl_opener.getinfo(value)
            except TypeError as ex:
                logger.debug("Exception for %s - %s : %s", field, value, ex)
                continue
            except Exception as ex:  # pylint: disable=broad-except
                logger.warning(
                    "Exception for %s - %s : %s: %s",
                    field,
                    value,
                    ex.__class__.__name__,
                    ex,
                )
                continue
            else:
                self._response_info[field] = field_data
        self._url = self._response_info.get("EFFECTIVE_URL")
        return self._response_info

    @property
    def request(self):
        return self._request

    @property
    def url(self):
        if not self._url:
            self._get_curl_info()
        return self._url

    @property
    def status_code(self):
        if not self._status_code:
            self._status_code = int(self._curl_opener.getinfo(pycurl.HTTP_CODE))
        return self._status_code

    @property
    def content(self):
        """Returns decoded self._content
        """
        if not self._content:
            self._content = self._body_otput.getvalue()
        return self._content

    @property
    def json(self):
        """Returns the json-encoded content of a response
        """
        try:
            return json.loads(self.content)
        except InterfaceError:
            return None

    @staticmethod
    def _split_headers_blocks(raw_headers):
        # logger.debug('Reponse._split_headers_blocks %s', raw_headers)
        i = 0
        blocks = []
        for item in raw_headers.strip().split("\r\n"):
            if item.startswith("HTTP"):
                blocks.append([item])
                i = len(blocks) - 1
            elif item:
                blocks[i].append(item)
        return blocks

    def _parse_headers_raw(self):
        """Parse response headers and save as instance vars
        """
        logger.debug("Reponse._parse_headers_raw")

        def parse_header_block(raw_block):
            """Parse headers block
            Arguments:
            - `block`: raw header block
            Returns:
            - `headers_list`:
            """
            # logger.debug('Reponse._parse_headers_raw.parse_header_block %s', raw_block)
            block_headers = []
            for header in raw_block:
                if not header:
                    continue
                elif not header.startswith("HTTP"):
                    field, value = [u.strip() for u in header.split(":", 1)]
                    if field.startswith("Location"):
                        # maybe not good
                        if not value.startswith("http"):
                            value = urljoin(self.url, value)
                        self._history.append(value)
                    if value[:1] == value[-1:] == '"':
                        value = value[1:-1]  # strip "
                    block_headers.append((field, value.strip()))
                elif header.startswith("HTTP"):
                    # extract version, code, message from first header
                    try:
                        version, code, message = HTTP_GENERAL_RESPONSE_HEADER.findall(
                            header
                        )[0]
                        self._reason = message
                    except Exception as ex:  # pylint: disable=broad-except
                        logger.warning(
                            "Except %s while looking at header %s", ex, header
                        )
                        continue
                    else:
                        block_headers.append((version, code, message))
                else:
                    # raise InterfaceError("Wrong header field")
                    pass
            return block_headers

        raw_headers = self._headers_output.getvalue().decode("iso-8859-1")

        for raw_block in self._split_headers_blocks(raw_headers):
            block = parse_header_block(raw_block)
            self._headers_history.append(block)

        if self._headers_history:
            last_header = self._headers_history[-1]
            self._headers = last_header[1:]  # CaseInsensitiveDict

        if not self._history:
            self._history.append(self.url)

    @property
    def reason(self):
        if not self._reason:
            self._parse_headers_raw()
        return self._reason

    @property
    def headers(self):
        """Returns response headers
        """
        if not self._headers:
            self._parse_headers_raw()
        # logger.debug("headers: %s %s", self._headers.__class__.__name__, self._headers)
        return self._headers

    @property
    def headers_history(self):
        if not self._headers_history:
            self._parse_headers_raw()
        return self._headers_history

    @property
    def history(self):
        """Returns redirects history list
        :return: list of `Response` objects
        """
        if not self._history:
            self._parse_headers_raw()
        return self._history


def request(
    method,
    url,
    params=None,
    data=None,
    headers=None,
    timeout=None,
    allow_redirects=True,
    max_redirects=10,
    cert_file=None,
    key_file=None,
    verify=False,
    encode_query=True,
    domain_lookup_info=None,
):
    """Construct and sends a Request object. Returns :class `Response`.
    Arguments:
    - `url`: (string) resource url
    - `method`: (string) one of `self.SUPPORTED_METHODS`
    - `data`: (dict, duple, string) data to send as Content-Disposition form-data
    - `params`: (dict, tuple) of GET params (?param1=value1&param2=value2)
    - `headers`: (dict, tuple) of request headers
    - `cookies`: (dict, tuple or CookieJar) of cookies
    - `files`: (dict, tuple or list) of files
       Example:
           (('field_file_name', '/path/to/file.txt'),
           ('field_file_name', open('/path/to/file.txt')),
           ('multiple_files_field', (open("/path/to/file.1.txt"), open("/path/to/file.1.txt"))),
           ('multiple_files_field', ("/path/to/file.1.txt", "/path/to/file.1.txt")))
    - `timeout`: (float) connection time out
    - `connection_timeout`: (float)
    - `allow_redirects`: (bool) follow redirects parametr
    - `proxy`: (dict, tuple or list) of proxies
       Examples:
           ('http', ('127.0.0.1', 9050))
           ('http', ('127.0.0.1', 9050, ('username', 'password'))
           TODO: multiple proxies support?
           (('http', ('127.0.0.1', 9050)),
            ('socks', ('127.0.0.1', 9050, ('username', 'password')))
    - `auth`: (dict, tuple or list) for resource base auth
    - `network_interface`: (str) use given interface for request
    - `use_gzip`: (bool) accept gzipped data
    - `validate_cert`: (bool)
    - `ca_certs`:
    - `cert`: (string) use for client-side certificate authentication
    - `debug`: (bool) use for `pycurl.DEBUGFUNCTION`
    - `user_agent`: (string) user agent
    - `ip_v6`: (bool) use ipv6 protocol
    - `options`: (list, tuple) low level curl options
    Returns:
    - `response`: :Response instance
    """

    req = Request(
        method=method,
        url=url,
        params=params,
        data=data,
        headers=headers,
        timeout=timeout,
        allow_redirects=allow_redirects,
        max_redirects=max_redirects,
        cert_file=cert_file,
        key_file=key_file,
        validate_cert=verify,
        encode_query=encode_query,
        domain_lookup_info=domain_lookup_info,
    )

    req.send()

    return req.response


PYCURL_AGENT_ERRORS = [
    pycurl.E_UNSUPPORTED_PROTOCOL,
    pycurl.E_FAILED_INIT,
    pycurl.E_OUT_OF_MEMORY,
    pycurl.E_BAD_FUNCTION_ARGUMENT,
]
PYCURL_SETUP_ERRORS = [pycurl.E_URL_MALFORMAT]

# pylint: disable=line-too-long
PYCURL_ERROR_LOOKUP = {
    pycurl.E_ABORTED_BY_CALLBACK: 'Aborted by callback. A callback returned "abort" to libcurl.',
    pycurl.E_AGAIN: "Socket is not ready for send/recv wait till it's ready and try again. This return code is only returned from curl_easy_recv and curl_easy_send (Added in 7.18.2)",
    pycurl.E_BAD_CONTENT_ENCODING: "Unrecognized transfer encoding.",
    pycurl.E_BAD_DOWNLOAD_RESUME: "The download could not be resumed because the specified offset was out of the file boundary.",
    pycurl.E_BAD_FUNCTION_ARGUMENT: "Internal error. A function was called with a bad parameter.",
    pycurl.E_CHUNK_FAILED: "Chunk callback reported error.",
    pycurl.E_CONV_FAILED: "Character conversion failed.",
    pycurl.E_CONV_REQD: "Caller must register conversion callbacks.",
    pycurl.E_COULDNT_CONNECT: "Failed to connect() to host or proxy.",
    pycurl.E_COULDNT_RESOLVE_HOST: "Couldn't resolve host. The given remote host was not resolved.",
    pycurl.E_COULDNT_RESOLVE_PROXY: "Couldn't resolve proxy. The given proxy host could not be resolved.",
    pycurl.E_FAILED_INIT: "Very early initialization code failed. This is likely to be an internal error or problem, or a resource problem where something fundamental couldn't get done at init time.",
    pycurl.E_FILE_COULDNT_READ_FILE: "A file given with FILE:// couldn't be opened. Most likely because the file path doesn't identify an existing file. Did you check file permissions?",
    pycurl.E_FILESIZE_EXCEEDED: "Maximum file size exceeded.",
    pycurl.E_FTP_ACCEPT_FAILED: "While waiting for the server to connect back when an active FTP session is used, an error code was sent over the control connection or similar.",
    pycurl.E_FTP_ACCEPT_TIMEOUT: "During an active FTP session while waiting for the server to connect, the CURLOPT_ACCEPTTIMEOUT_MS (or the internal default) timeout expired.",
    pycurl.E_FTP_BAD_FILE_LIST: "Unable to parse FTP file list (during FTP wildcard downloading).",
    pycurl.E_FTP_CANT_GET_HOST: "An internal failure to lookup the host used for the new connection.",
    pycurl.E_FTP_COULDNT_RETR_FILE: "This was either a weird reply to a 'RETR' command or a zero byte transfer complete.",
    pycurl.E_FTP_COULDNT_SET_TYPE: "Received an error when trying to set the transfer mode to binary or ASCII.",
    pycurl.E_FTP_COULDNT_USE_REST: "The FTP REST command returned error. This should never happen if the server is sane.",
    pycurl.E_FTP_PORT_FAILED: "The FTP PORT command returned error. This mostly happens when you haven't specified a good enough address for libcurl to use. See CURLOPT_FTPPORT.",
    pycurl.E_FTP_PRET_FAILED: "The FTP server does not understand the PRET command at all or does not support the given argument. Be careful when using CURLOPT_CUSTOMREQUEST, a custom LIST command will be sent with PRET CMD before PASV as well. (Added in 7.20.0)",
    pycurl.E_FTP_WEIRD_227_FORMAT: "FTP servers return a 227-line as a response to a PASV command. If libcurl fails to parse that line, this return code is passed back.",
    pycurl.E_FTP_WEIRD_PASS_REPLY: "After having sent the FTP password to the server, libcurl expects a proper reply. This error code indicates that an unexpected code was returned.",
    pycurl.E_FTP_WEIRD_PASV_REPLY: "libcurl failed to get a sensible result back from the server as a response to either a PASV or a EPSV command. The server is flawed.",
    pycurl.E_FTP_WEIRD_SERVER_REPLY: "After connecting to a FTP server, libcurl expects to get a certain reply back. This error code implies that it got a strange or bad reply. The given remote server is probably not an OK FTP server.",
    pycurl.E_FUNCTION_NOT_FOUND: "Function not found. A required zlib function was not found.",
    pycurl.E_GOT_NOTHING: "Nothing was returned from the server, and under the circumstances, getting nothing is considered an error.",
    pycurl.E_HTTP_POST_ERROR: "This is an odd error that mainly occurs due to internal confusion.",
    pycurl.E_HTTP_RETURNED_ERROR: "This is returned if CURLOPT_FAILONERROR is set TRUE and the HTTP server returns an error code that is >= 400.",
    pycurl.E_INTERFACE_FAILED: "Interface error. A specified outgoing interface could not be used. Set which interface to use for outgoing connections' source IP address with CURLOPT_INTERFACE.",
    pycurl.E_LDAP_CANNOT_BIND: "LDAP cannot bind. LDAP bind operation failed.",
    pycurl.E_LDAP_INVALID_URL: "Invalid LDAP URL.",
    pycurl.E_LDAP_SEARCH_FAILED: "LDAP search failed.",
    pycurl.E_LOGIN_DENIED: "The remote server denied curl to login (Added in 7.13.1)",
    pycurl.E_NOT_BUILT_IN: "A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision. This means that a feature or option was not enabled or explicitly disabled when libcurl was built and in order to get it to function you have to get a rebuilt libcurl.",
    pycurl.E_OPERATION_TIMEDOUT: "Operation timeout. The specified time-out period was reached according to the conditions.",
    pycurl.E_OUT_OF_MEMORY: "A memory allocation request failed. This is serious badness and things are severely screwed up if this ever occurs.",
    pycurl.E_PARTIAL_FILE: "A file transfer was shorter or larger than expected. This happens when the server first reports an expected transfer size, and then delivers data that doesn't match the previously given size.",
    pycurl.E_PEER_FAILED_VERIFICATION: "The remote server's SSL certificate or SSH md5 fingerprint was deemed not OK.",
    pycurl.E_QUOTE_ERROR: 'When sending custom "QUOTE" commands to the remote server, one of the commands returned an error code that was 400 or higher (for FTP) or otherwise indicated unsuccessful completion of the command.',
    pycurl.E_RANGE_ERROR: "The server does not support or accept range requests.",
    pycurl.E_READ_ERROR: "There was a problem reading a local file or an error returned by the read callback.",
    pycurl.E_RECV_ERROR: "Failure with receiving network data.",
    pycurl.E_REMOTE_ACCESS_DENIED: "We were denied access to the resource given in the URL. For FTP, this occurs while trying to change to the remote directory.",
    pycurl.E_REMOTE_DISK_FULL: "Out of disk space on the server.",
    pycurl.E_REMOTE_FILE_EXISTS: "File already exists and will not be overwritten.",
    pycurl.E_REMOTE_FILE_NOT_FOUND: "The resource referenced in the URL does not exist.",
    pycurl.E_RTSP_CSEQ_ERROR: "Mismatch of RTSP CSeq numbers.",
    pycurl.E_RTSP_SESSION_ERROR: "Mismatch of RTSP Session Identifiers.",
    pycurl.E_SEND_ERROR: "Failed sending network data.",
    pycurl.E_SEND_FAIL_REWIND: "When doing a send operation curl had to rewind the data to retransmit, but the rewinding operation failed.",
    pycurl.E_SSH: "An unspecified error occurred during the SSH session.",
    pycurl.E_SSL_CACERT: "Peer certificate cannot be authenticated with known CA certificates.",
    pycurl.E_SSL_CACERT_BADFILE: "Problem with reading the SSL CA cert (path? access rights?)",
    pycurl.E_SSL_CERTPROBLEM: "problem with the local client certificate.",
    pycurl.E_SSL_CIPHER: "Couldn't use specified cipher.",
    pycurl.E_SSL_CONNECT_ERROR: "A problem occurred somewhere in the SSL/TLS handshake. You really want the error buffer and read the message there as it pinpoints the problem slightly more. Could be certificates (file formats, paths, permissions), passwords, and others.",
    pycurl.E_SSL_CRL_BADFILE: "Failed to load CRL file (Added in 7.19.0)",
    pycurl.E_SSL_ENGINE_INITFAILED: "Initiating the SSL Engine failed.",
    pycurl.E_SSL_ENGINE_NOTFOUND: "The specified crypto engine wasn't found.",
    pycurl.E_SSL_ENGINE_SETFAILED: "Failed setting the selected SSL crypto engine as default!",
    pycurl.E_SSL_ISSUER_ERROR: "Issuer check failed (Added in 7.19.0)",
    pycurl.E_SSL_SHUTDOWN_FAILED: "Failed to shut down the SSL connection.",
    pycurl.E_TELNET_OPTION_SYNTAX: "A telnet option string was Illegally formatted.",
    pycurl.E_TFTP_ILLEGAL: "Illegal TFTP operation.",
    pycurl.E_TFTP_NOSUCHUSER: "This error should never be returned by a properly functioning TFTP server.",
    pycurl.E_TFTP_NOTFOUND: "File not found on TFTP server.",
    pycurl.E_TFTP_PERM: "Permission problem on TFTP server.",
    pycurl.E_TFTP_UNKNOWNID: "Unknown TFTP transfer ID.",
    pycurl.E_TOO_MANY_REDIRECTS: "Too many redirects. When following redirects, libcurl hit the maximum amount. Set your limit with CURLOPT_MAXREDIRS.",
    pycurl.E_UNKNOWN_OPTION: "An option passed to libcurl is not recognized/known. Refer to the appropriate documentation. This is most likely a problem in the program that uses libcurl. The error buffer might contain more specific information about which exact option it concerns.",
    pycurl.E_UNSUPPORTED_PROTOCOL: "The URL you passed to libcurl used a protocol that this libcurl does not support. The support might be a compile-time option that you didn't use, it can be a misspelled protocol string or just a protocol libcurl has no code for.",
    pycurl.E_UPLOAD_FAILED: "Failed starting the upload. For FTP, the server typically denied the STOR command. The error buffer usually contains the server's explanation for this.",
    pycurl.E_URL_MALFORMAT: "The URL was not properly formatted.",
    pycurl.E_USE_SSL_FAILED: "Requested FTP SSL level failed.",
    pycurl.E_WRITE_ERROR: "An error occurred when writing received data to a local file, or an error was returned to libcurl from a write callback.",
    # Not in libcurl 7.26
    # pycurl.E_NO_CONNECTION_AVAILABLE: "(For internal use only, will never be returned by libcurl) No connection available, the session will be queued. (added in 7.30.0)",
    # Not in libcurl 7.35
    # pycurl.E_SSL_PINNEDPUBKEYNOTMATCH: "Failed to match the pinned key specified with CURLOPT_PINNEDPUBLICKEY.",
    # pycurl.E_HTTP2: "A problem was detected in the HTTP2 framing layer. This is somewhat generic and can be one out of several problems, see the error buffer for details.",
    # Not yet in libcurl 7.40:
    # pycurl.E_SSL_INVALIDCERTSTATUS: "Status returned failure when asked with CURLOPT_SSL_VERIFYSTATUS.",
}
