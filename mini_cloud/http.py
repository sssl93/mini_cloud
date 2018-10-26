"""
Subclass for httplib.HTTPSConnection with optional certificate name
verification, depending on mini_cloud.security settings.
"""

import os
import warnings
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from urllib3 import HTTPConnectionPool
from mini_cloud import security
from mini_cloud.utils.py3 import urlparse, PY3
import gevent

__all__ = [
    'MiniCloudBaseConnection',
    'MiniCloudConnection',
    'HttpLibResponseProxy',
    'SignedHTTPSAdapter'
]

ALLOW_REDIRECTS = True

HTTP_PROXY_ENV_VARIABLE_NAME = 'http_proxy'


class SignedHTTPSAdapter(HTTPAdapter):
    def __init__(self, cert_file, key_file):
        self.cert_file = cert_file
        self.key_file = key_file
        self.pool_manager = None
        super(SignedHTTPSAdapter, self).__init__()

    def init_pool_manager(self, connections, maxsize, block=False):
        self.pool_manager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block,
            cert_file=self.cert_file,
            key_file=self.key_file)


class MiniCloudBaseConnection(object):
    """
    Base connection class to inherit from.

    Note: This class should not be instantiated directly.
    """

    session = None

    proxy_scheme = None
    proxy_host = None
    proxy_port = None

    proxy_username = None
    proxy_password = None

    http_proxy_used = False

    ca_cert = None

    def __init__(self):
        self.session = requests.Session()

    def set_http_proxy(self, proxy_url):
        """
        Set a HTTP proxy which will be used with this connection.

        :param proxy_url: Proxy URL (e.g. http://<hostname>:<port> without
                          authentication and
                          http://<username>:<password>@<hostname>:<port> for
                          basic auth authentication information.
        :type proxy_url: ``str``
        """
        result = self._parse_proxy_url(proxy_url=proxy_url)
        scheme = result[0]
        host = result[1]
        port = result[2]
        username = result[3]
        password = result[4]

        self.proxy_scheme = scheme
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_username = username
        self.proxy_password = password
        self.http_proxy_used = True

        self.session.proxies = {
            self.proxy_scheme: proxy_url
        }

    def _parse_proxy_url(self, proxy_url):
        """
        Parse and validate a proxy URL.

        :param proxy_url: Proxy URL (e.g. http://hostname:3128)
        :type proxy_url: ``str``

        :rtype: ``tuple`` (``scheme``, ``hostname``, ``port``)
        """
        parsed = urlparse.urlparse(proxy_url)

        if parsed.scheme != 'http':
            raise ValueError('Only http proxies are supported')

        if not parsed.hostname or not parsed.port:
            raise ValueError('proxy_url must be in the following format: '
                             'http://<proxy host>:<proxy port>')

        proxy_scheme = parsed.scheme
        proxy_host, proxy_port = parsed.hostname, parsed.port

        netloc = parsed.netloc

        if '@' in netloc:
            username_password = netloc.split('@', 1)[0]
            split = username_password.split(':', 1)

            if len(split) < 2:
                raise ValueError('URL is in an invalid format')

            proxy_username, proxy_password = split[0], split[1]
        else:
            proxy_username = None
            proxy_password = None

        return (proxy_scheme, proxy_host, proxy_port, proxy_username,
                proxy_password)

    def _setup_verify(self):
        self.verify = security.VERIFY_SSL_CERT

    def _setup_ca_cert(self, **kwargs):
        # simulating keyword-only argument in Python 2
        ca_certs_path = kwargs.get('ca_cert', security.CA_CERTS_PATH)

        if self.verify is False:
            pass
        else:
            if isinstance(ca_certs_path, list):
                msg = (
                    'Providing a list of CA trusts is no longer supported '
                    'since libcloud 2.0. Using the first element in the list. '
                    'See http://libcloud.readthedocs.io/en/latest/other/'
                    'changes_in_2_0.html#providing-a-list-of-ca-trusts-is-no-'
                    'longer-supported')
                warnings.warn(msg, DeprecationWarning)
                self.ca_cert = ca_certs_path[0]
            else:
                self.ca_cert = ca_certs_path

    def _setup_signing(self, cert_file=None, key_file=None):
        """
        Setup request signing by mounting a signing
        adapter to the session
        """
        self.session.mount('https://', SignedHTTPSAdapter(cert_file, key_file))


class MiniCloudConnection(MiniCloudBaseConnection):
    timeout = None
    host = None
    response = None
    pool = None

    def __init__(self, host, port, secure=None, **kwargs):
        scheme = 'https' if secure is not None and secure else 'http'
        self.host = '{0}://{1}{2}'.format(
            'https' if port == 443 else scheme,
            host,
            ":{0}".format(port) if port not in (80, 443) else ""
        )
        # Support for HTTP proxy
        proxy_url_env = os.environ.get(HTTP_PROXY_ENV_VARIABLE_NAME, None)
        proxy_url = kwargs.pop('proxy_url', proxy_url_env)

        self._setup_verify()
        self._setup_ca_cert()

        super(MiniCloudConnection, self).__init__()

        if 'cert_file' in kwargs or 'key_file' in kwargs:
            self._setup_signing(**kwargs)

        if proxy_url:
            self.set_http_proxy(proxy_url=proxy_url)
        self.session.timeout = kwargs.get('timeout', 60)

        self.pool = HTTPConnectionPool(host=host, port=port, maxsize=20)

    @property
    def verification(self):
        """
        The option for SSL verification given to underlying requests
        """
        return self.ca_cert if self.ca_cert is not None else self.verify

    def request(self, method, url, body=None, headers=None, raw=False, stream=False):
        url = urlparse.urljoin(self.host, url)
        headers = self._normalize_headers(headers=headers)

        self.response = self.session.request(
            method=method.lower(),
            url=url,
            data=body,
            headers=headers,
            allow_redirects=ALLOW_REDIRECTS,
            stream=stream,
            verify=self.verification
        )

    def async_request(self, method, url, body=None, headers=None, raw=False, stream=False):
        url = urlparse.urljoin(self.host, url)
        headers = self._normalize_headers(headers=headers)
        conn = self.pool._get_conn()
        conn.request(method=method, url=url, headers=headers, body=body)
        return conn

    def get_async_response(self, conn):
        return conn.getresponse()

    def gevent_request(self, method, url, body=None, headers=None, raw=False, stream=False):
        return gevent.spawn_later(0, self.request, *(method, url, body, headers, raw, stream))

    def prepared_request(self, method, url, body=None, headers=None, raw=False, stream=False):
        headers = self._normalize_headers(headers=headers)

        req = requests.Request(method, ''.join([self.host, url]), data=body, headers=headers)

        prepped = self.session.prepare_request(req)

        prepped.body = body

        self.response = self.session.send(
            prepped,
            stream=raw,
            verify=self.ca_cert if self.ca_cert is not None else self.verify)

    def getresponse(self):
        return self.response

    def getheaders(self):
        # urlib decoded response body, libcloud has a bug
        # and will not check if content is gzipped, so let's
        # remove headers indicating compressed content.
        if 'content-encoding' in self.response.headers:
            del self.response.headers['content-encoding']
        return self.response.headers

    @property
    def status(self):
        return self.response.status_code

    @property
    def reason(self):
        return None if self.response.status_code > 400 else self.response.text

    def connect(self):  # pragma: no cover
        pass

    def read(self):
        return self.response.content

    def close(self):  # pragma: no cover
        # return connection back to pool
        self.response.close()

    @staticmethod
    def _normalize_headers(headers):
        headers = headers or {}

        # all headers should be strings
        for key, value in headers.items():
            if isinstance(value, (int, float)):
                headers[key] = str(value)

        return headers


class HttpLibResponseProxy(object):
    """
    Provides a proxy pattern around the :class:`requests.Reponse`
    object to a :class:`httplib.HTTPResponse` object
    """

    def __init__(self, response):
        self._response = response

    def read(self, amt=None):
        return self._response.text

    def getheader(self, name, default=None):
        """
        Get the contents of the header name, or default
        if there is no matching header.
        """
        if name in self._response.headers.keys():
            return self._response.headers[name]
        else:
            return default

    def getheaders(self):
        """
        Return a list of (header, value) tuples.
        """
        if PY3:
            return list(self._response.headers.items())
        else:
            return self._response.headers.items()

    @property
    def status(self):
        return self._response.status_code

    @property
    def reason(self):
        return self._response.reason

    @property
    def version(self):
        # requests doesn't expose this
        return '11'

    @property
    def body(self):
        # NOTE: We use property to avoid saving whole response body into RAM
        # See https://github.com/apache/libcloud/pull/1132 for details
        return self._response.content
