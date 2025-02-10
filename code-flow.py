from input import start_input_thread
from jwcrypto import jwt
from LoopbackServer import LoopbackServer
from oidc_common import OpenIDConfiguration, ClientConfiguration, get_client_state
import argparse
import json
import logging
import os
import requests
import sys
import webbrowser

# command arguments
# --browser|-b
# --provider|-p
# --openid-configuration|-o
# --client-configuration|-c
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
DEFAULT_CLIENT_CONFIGURATION = "code-flow.json"

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

# provider discovery and configuration

provider = OpenIDConfiguration(args.openid_configuration)

# client configuration

client = ClientConfiguration(args.client_configuration, scope=args.scope)

# create and start http server

with LoopbackServer(provider, client, vars(args)) as httpd:
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

# token request with authorization code

body = {
    "grant_type": "authorization_code",
    "redirect_uri": httpd.redirect_uri,
    "code": httpd.authorization_response["code"][0],
    "code_verifier": state.code_verifier,
}
# client authentication
if client.client_secret is None:
    body["client_id"] = client.client_id
    auth = None
else:
    auth = (client.client_id, client.client_secret)
    logging.debug(f"token_request_auth = {auth}")

logging.debug(f"token_request_params = {body}")
logging.debug(f"token_request = {provider.token_endpoint}")
r = requests.post(provider.token_endpoint, data=body, auth=auth)
token_response = r.json()
logging.debug(f"token_response = {token_response}")

# handles error from token response

if "error" in token_response:
    raise Exception(token_response["error"])

# invoke userinfo endpoint with access token

if provider.userinfo_endpoint is not None and "access_token" in token_response:
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token_response["access_token"],
    }
    r = requests.get(provider.userinfo_endpoint, headers=headers)
    r.raise_for_status()
    logging.info(json.dumps(r.json(), indent=2))

# id_token

if provider.provider_jwks is not None and "id_token" in token_response:
    # id_token - signature
    token = jwt.JWT(key=provider.provider_jwks, jwt=token_response["id_token"])
    id_token = json.loads(token.claims)
    # verify nonce
    if state.nonce != id_token["nonce"]:
        raise Exception("invalid nonce")
    logging.info(json.dumps(id_token, indent=2))
