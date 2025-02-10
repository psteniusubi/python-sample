from datetime import datetime, timedelta
from input import start_input_thread
from jwcrypto import jwt, jwe
from LoopbackServer import LoopbackServer
from oidc_common import OpenIDConfiguration, ClientConfiguration, get_client_state
import argparse
import json
import logging
import os
import requests
import sys
import uuid
import webbrowser

# command arguments
# --browser|-b
# --provider|-p
# --openid-configuration|-o
# --client-configuration|-c
# --client-jwks|-j
# --scope|-s
# --acr-values|-a
# --ui-locales|-l
# --login-hint
# --prompt
# --max-age
# --ftn-spname|-n
# --template
# --verbose

DEFAULT_PROVIDER = "https://login.example.ubidemo.com/uas"
DEFAULT_CLIENT_CONFIGURATION = "code-flow-with-jwsreq.json"
DEFAULT_CLIENT_JWKS = "code-flow-with-jwsreq.jwk"

parser = argparse.ArgumentParser(description="OpenID Connect client")
parser.add_argument(
    "-b", "--browser", default=os.getenv("BROWSER"), help="Browser command"
)
parser.add_argument(
    "-p",
    "--provider",
    default=DEFAULT_PROVIDER,
    help=f"Name of OpenID Provider, default {DEFAULT_PROVIDER}",
)
parser.add_argument(
    "-o",
    "--openid-configuration",
    help=f"OpenID Provider metadata, default derived from --provider argument {DEFAULT_PROVIDER}/.well-known/openid-configuration",
)
parser.add_argument(
    "-c",
    "--client-configuration",
    default=DEFAULT_CLIENT_CONFIGURATION,
    help=f"OpenID Relying Party configuration, default {DEFAULT_CLIENT_CONFIGURATION}",
)
parser.add_argument(
    "-j",
    "--client-jwks",
    default=DEFAULT_CLIENT_JWKS,
    help=f"OpenID Relying Party jwks, default {DEFAULT_CLIENT_JWKS}",
)
parser.add_argument(
    "-s",
    "--scope",
    help="Scope value, default either from client configuration or value openid",
)
parser.add_argument("-a", "--acr-values", help="ACR value")
parser.add_argument("-l", "--ui-locales", help="User interface locale")
parser.add_argument("--login-hint", help="Login identifier")
parser.add_argument("--prompt", help="Prompt for reauthentication")
parser.add_argument("--max-age", type=int, help="Maximum authentication age")
parser.add_argument("-n", "--ftn-spname", help="FTN application name (FTN extension)")
parser.add_argument("--template", help="User interface template name (SSO extension)")
parser.add_argument("--verbose", help="Verbose output", action="store_true")
args = parser.parse_args()
if args.openid_configuration is None:
    args.openid_configuration = f"{args.provider}/.well-known/openid-configuration"

# logging

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

# browser

if args.browser is not None:
    webbrowser.register(
        "browser", None, webbrowser.BackgroundBrowser(args.browser), preferred=True
    )

# provider discovery

provider = OpenIDConfiguration(args.openid_configuration)

# client configuration

client = ClientConfiguration(
    args.client_configuration, client_jwks=args.client_jwks, scope=args.scope
)

# http server


class JwsreqServer(LoopbackServer):
    def authorization_request_params(self):
        params = super().authorization_request_params()
        params["iss"] = self.client.client_id
        params["aud"] = (
            self.provider.issuer,
            self.provider.token_endpoint,
            self.provider.authorization_endpoint,
        )
        params["exp"] = int((datetime.now() + timedelta(minutes=10)).timestamp())
        params["jti"] = str(uuid.uuid4())
        logging.debug(f"authorization_request_params = {params}")

        # request object - sign
        token = client.sign_request_object(provider, params)

        # request object - encrypt
        token = client.encrypt_request_object(provider, token)

        p = {"request": token.serialize()}
        # request object - copy signed parameters to request parameters
        for i in ("response_type", "client_id", "scope", "template"):
            if i in params and params[i] is not None:
                p[i] = params[i]
        return p


# create and start http server


with JwsreqServer(provider, client, vars(args)) as httpd:
    # launch web browser
    print(httpd.base_uri)
    webbrowser.open(httpd.base_uri)
    # wait for input
    start_input_thread("Press enter to stop\r\n", httpd.done)
    # process http requests until authorization response is received
    if httpd.wait_authorization_response() is None:
        sys.exit()

# handles error from authorization response

if "error" in httpd.authorization_response:
    raise Exception(httpd.authorization_response["error"][0])

# verify state

state = get_client_state(httpd.authorization_response)

# client assertion, signed

claims = {
    "iss": client.client_id,
    "sub": client.client_id,
    "aud": (provider.issuer, provider.token_endpoint),
    "exp": int((datetime.now() + timedelta(minutes=10)).timestamp()),
    "jti": str(uuid.uuid4()),
}
logging.debug(f"client_assertion_claims = {claims}")
token = client.sign_client_assertion(provider, claims)

# token request with authorization code and client assertion

body = {
    "client_id": client.client_id,
    "grant_type": "authorization_code",
    "redirect_uri": httpd.redirect_uri,
    "client_assertion": token.serialize(),
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "code": httpd.authorization_response["code"][0],
    "code_verifier": state.code_verifier,
}
logging.debug(f"token_request_params = {body}")
logging.debug(f"token_request = {provider.token_endpoint}")
r = requests.post(provider.token_endpoint, data=body)
token_response = r.json()
logging.debug(f"token_response = {token_response}")

# handles error from token response

if "error" in token_response:
    raise Exception(token_response["error"])

# id token - decrypt

plaintext = None
try:
    token = jwe.JWE.from_jose_token(token_response["id_token"])
    token.decrypt(client.client_jwks)
    plaintext = token.plaintext.decode("utf-8")
    logging.debug(f"id_token = {plaintext}")
except jwe.InvalidJWEData as e:
    logging.debug("JWE.decrypt", e)
    plaintext = token_response["id_token"]

# id token - signature

token = jwt.JWT(key=provider.provider_jwks, jwt=plaintext)
id_token = json.loads(token.claims)

# verify nonce

if state.nonce != id_token["nonce"]:
    raise Exception("invalid nonce")

logging.info(json.dumps(id_token, indent=2))
