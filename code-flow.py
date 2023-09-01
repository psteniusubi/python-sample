import requests
import webbrowser
from LoopbackServer import LoopbackServer
import json
import logging
import argparse

# command arguments
# --provider|-p --openid-configuration|-o --client-configuration|-c --scope|-s --acr-values|-a --ui-locales|-l --ftn-spname|-n

DEFAULT_PROVIDER = "https://login.example.ubidemo.com/uas"
DEFAULT_CLIENT_CONFIGURATION = "code-flow.json"

parser = argparse.ArgumentParser(description='OpenID Connect client')
parser.add_argument("-p", "--provider", default=DEFAULT_PROVIDER, help=f"Name of OpenID Provider, default {DEFAULT_PROVIDER}")
parser.add_argument("-o", "--openid-configuration", help=f"OpenID Provider metadata, default derived from --provider argument {DEFAULT_PROVIDER}/.well-known/openid-configuration")
parser.add_argument("-c", "--client-configuration", default=DEFAULT_CLIENT_CONFIGURATION, help=f"OpenID Relying Party configuration, default {DEFAULT_CLIENT_CONFIGURATION}")
parser.add_argument("-s", "--scope", help="Scope value, default either from client configuration or value openid")
parser.add_argument("-a", "--acr-values", help="ACR value")
parser.add_argument("-l", "--ui-locales", help="User interface locale")
parser.add_argument("-n", "--ftn-spname", help="FTN application name")
parser.add_argument("--verbose", help="Verbose output", action="store_true")
args = parser.parse_args()
if args.openid_configuration is None:
    args.openid_configuration = f"{args.provider}/.well-known/openid-configuration"

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

# provider discovery and configuration

if args.openid_configuration.startswith("https:") or args.openid_configuration.startswith("http:"):
    logging.debug(f"GET {args.openid_configuration}")
    r = requests.get(args.openid_configuration)
    r.raise_for_status()
    provider = r.json()
else:
    logging.debug(f"read {args.openid_configuration}")
    with open(args.openid_configuration, "r", encoding="utf-8-sig") as fp:
        provider = json.loads(fp.read())

if not "authorization_endpoint" in provider:
    raise Exception("missing authorization_endpoint")
if not "token_endpoint" in provider:
    raise Exception("missing token_endpoint")
if not "userinfo_endpoint" in provider:
    raise Exception("missing userinfo_endpoint")

# client configuration

logging.debug(f"read {args.client_configuration}")
with open(args.client_configuration, "r", encoding="utf-8-sig") as fp:
    client = json.loads(fp.read())

if not "client_id" in client:
    raise Exception("missing client_id")
if not "client_secret" in client:
    raise Exception("missing client_secret")

if args.scope is None:
    if "scope" in client:
        args.scope = client["scope"]
    else:
        args.scope = "openid"

# create and start http server

with LoopbackServer(provider, client, vars(args)) as httpd:
    # launch web browser
    logging.info(f"http server {httpd.base_uri}")
    webbrowser.open(httpd.base_uri)
    # process http requests until authorization response is received
    while httpd.active:
        httpd.handle_request()

# handles error from authorization response

if "error" in httpd.authorization_response:
    raise Exception(httpd.authorization_response["error"][0])

# verify state

if httpd.state != httpd.authorization_response["state"][0]:
    raise Exception("invalid state")

# token request with authorization code

body = {
    "grant_type": "authorization_code",
    "redirect_uri": httpd.redirect_uri,
    "code": httpd.authorization_response["code"][0],
    "code_verifier": httpd.code_verifier.decode("utf-8")
}
auth = (
    client["client_id"],
    client["client_secret"]
)
r = requests.post(provider["token_endpoint"], data=body, auth=auth)
token_response = r.json()

# handles error from token response

if "error" in token_response:
    raise Exception(token_response["error"])

# invoke userinfo endpoint with access token

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer " + token_response["access_token"]
}
r = requests.get(provider["userinfo_endpoint"], headers=headers)
r.raise_for_status()
logging.info(json.dumps(r.json(), indent=2))
