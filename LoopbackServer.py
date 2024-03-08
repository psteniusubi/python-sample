import http.server
import uuid
from urllib.parse import urlsplit
from urllib.parse import urlencode
from urllib.parse import parse_qs
from base64 import urlsafe_b64encode
import os
from hashlib import sha256
import logging
from oidc_common import OpenIDConfiguration, ClientConfiguration

# html page when browser invokes authorization response

html = """
<body onload="window.history.replaceState(null, null, location.pathname); window.close()">
<p>The operation was completed. You may close this window.</p>
<p><input type="button" onclick="window.close()" value="Close"></input></p>
</body>
"""


class LoopbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        httpd = self.server
        r = urlsplit(self.path)

        # handles authorization response
        if r.path == httpd.redirect_path:
            logging.debug(f"authorization_response = {self.path}")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = html.encode("utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
            httpd.authorization_response = parse_qs(r.query)
            # logging.debug(self.path)
            return

        # any other request generates authorization request
        url = httpd.authorization_request()
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()
        # logging.debug(str(url))


class LoopbackServer(http.server.HTTPServer):
    def __init__(
        self, provider: OpenIDConfiguration, client: ClientConfiguration, args={}
    ):
        super().__init__(("127.0.0.1", 0), LoopbackHandler)
        # configuration
        self.provider = provider
        self.client = client
        self.args = args
        # state
        self.state = None
        # nonce
        self.nonce = None
        # holds authorization response
        self.authorization_response = None
        # dynamic port with loopback handler
        self.__port = self.socket.getsockname()[1]

    @property
    def active(self):
        return self.authorization_response is None

    @property
    def port(self):
        return self.__port

    @property
    def base_uri(self):
        return f"http://localhost:{self.port}"

    @property
    def redirect_path(self):
        r = urlsplit(self.client.redirect_uri)
        return r.path

    @property
    def redirect_uri(self):
        return self.base_uri + self.redirect_path

    def generate_code_challenge(self):
        self.code_verifier = urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
        return urlsafe_b64encode(sha256(self.code_verifier).digest()).rstrip(b"=")

    def authorization_request_params(self):
        code_challenge = self.generate_code_challenge()
        self.state = str(uuid.uuid4())
        self.nonce = str(uuid.uuid4())
        params = {
            "response_type": "code",
            "client_id": self.client.client_id,
            "scope": self.client.scope,
            "redirect_uri": self.redirect_uri,
            "code_challenge": code_challenge.decode("utf-8"),
            "code_challenge_method": "S256",
            "state": self.state,
            "nonce": self.nonce,
        }
        for i in "scope", "acr_values", "ui_locales", "ftn_spname":
            if i in self.args and self.args[i] is not None:
                params[i] = self.args[i]
        return params

    def authorization_request(self):
        params = self.authorization_request_params()
        logging.debug(f"authorization_request_params = {params}")
        url = self.provider.authorization_endpoint + "?" + urlencode(params)
        logging.debug(f"authorization_request = {url}")
        return url
