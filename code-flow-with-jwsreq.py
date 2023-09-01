from urllib.parse import urlencode
import requests
import webbrowser
import json
import uuid
from datetime import datetime, timedelta
from jwcrypto import jwt, jwk
from LoopbackServer import LoopbackServer
import logging
import argparse

# command arguments
# --provider|-p
# --openid-configuration|-o
# --client-configuration|-c
# --client-jwks|-j
# --scope|-s
# --acr-values|-a
# --ui-locales|-l
# --ftn-spname|-n
# --verbose

DEFAULT_PROVIDER = "https://login.example.ubidemo.com/uas"
DEFAULT_CLIENT_CONFIGURATION = "code-flow-with-jwsreq.json"
DEFAULT_CLIENT_JWKS = "code-flow-with-jwsreq.jwk"

parser = argparse.ArgumentParser(description='OpenID Connect client')
parser.add_argument("-p", "--provider", default=DEFAULT_PROVIDER,
                    help=f"Name of OpenID Provider, default {DEFAULT_PROVIDER}")
parser.add_argument("-o", "--openid-configuration",
                    help=f"OpenID Provider metadata, default derived from --provider argument {DEFAULT_PROVIDER}/.well-known/openid-configuration")
parser.add_argument("-c", "--client-configuration", default=DEFAULT_CLIENT_CONFIGURATION,
                    help=f"OpenID Relying Party configuration, default {DEFAULT_CLIENT_CONFIGURATION}")
parser.add_argument("-j", "--client-jwks", default=DEFAULT_CLIENT_JWKS,
                    help=f"OpenID Relying Party jwks, default {DEFAULT_CLIENT_JWKS}")
parser.add_argument(
    "-s", "--scope", help="Scope value, default either from client configuration or value openid")
parser.add_argument("-a", "--acr-values", help="ACR value")
parser.add_argument("-l", "--ui-locales", help="User interface locale")
parser.add_argument("-n", "--ftn-spname", help="FTN application name")
parser.add_argument("--verbose", help="Verbose output", action="store_true")
args = parser.parse_args()
if args.openid_configuration is None:
    args.openid_configuration = f"{args.provider}/.well-known/openid-configuration"

# logging

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

# provider discovery

r = requests.get(args.openid_configuration)
r.raise_for_status()
provider = r.json()

r = requests.get(provider["jwks_uri"])
r.raise_for_status()
provider_jwks = jwk.JWKSet.from_json(r.text)
provider_jwk_enc = None

# find provider enc key from jwks_uri

for k in provider_jwks:
    t = k.export(private_key=False, as_dict=True)
    if "use" in t and t["use"] == "enc":
        provider_jwk_enc = k
        break
    if not "use" in t:
        provider_jwk_enc = k
        break

# client configuration

with open(args.client_configuration, "r", encoding="utf-8-sig") as fp:
    client = json.loads(fp.read())

with open(args.client_jwks, "r", encoding="utf-8-sig") as fp:
    client_jwks = jwk.JWKSet.from_json(fp.read())

if args.scope is None:
    if "scope" in client:
        args.scope = client["scope"]
    else:
        args.scope = "openid"

client_jwk_sig = None
client_jwk_enc = None

# find sig and enc keys from jwsreq.jwk

for k in client_jwks:
    t = k.export(private_key=True, as_dict=True)
    if "use" in t and t["use"] == "sig":
        client_jwk_sig = k
        continue
    if "use" in t and t["use"] == "enc":
        client_jwk_enc = k
        continue
    if not "use" in t:
        client_jwk_sig = k
        client_jwk_enc = k
        break

# http server


class JwsreqServer(LoopbackServer):
    def authorization_request_params(self):
        params = super().authorization_request_params()
        params["iss"] = self.client["client_id"]
        params["aud"] = (self.provider["issuer"], self.provider["token_endpoint"],
                         self.provider["authorization_endpoint"])
        params["exp"] = int(
            (datetime.now() + timedelta(minutes=10)).timestamp())
        params["jti"] = str(uuid.uuid4())
        logging.debug(f"authorization_request_params = {params}")
        # request object, signed and encrypted
        token = jwt.JWT(header={"alg": "RS256", "typ": "JWT",
                        "kid": client_jwk_sig.kid}, claims=params)
        token.make_signed_token(client_jwk_sig)
        token = jwt.JWT(header={"alg": "RSA-OAEP", "enc": "A128GCM", "cty": "JWT",
                        "kid": provider_jwk_enc.kid}, claims=token.serialize())
        token.make_encrypted_token(provider_jwk_enc)
        return {
            "request": token.serialize()
        }

# create and start http server


with JwsreqServer(provider, client, vars(args)) as httpd:
    # launch web browser
    print(httpd.base_uri)
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

# client assertion, signed

claims = {
    "iss": client["client_id"],
    "sub": client["client_id"],
    "aud": (provider["issuer"], provider["token_endpoint"]),
    "exp": int((datetime.now() + timedelta(minutes=10)).timestamp()),
    "jti": str(uuid.uuid4())
}
logging.debug(f'client_assertion_claims = {claims}')
token = jwt.JWT(header={"alg": "RS256", "typ": "JWT",
                "kid": client_jwk_sig.kid}, claims=claims)
token.make_signed_token(client_jwk_sig)

# token request with authorization code

body = {
    "client_id": client["client_id"],
    "grant_type": "authorization_code",
    "redirect_uri": httpd.redirect_uri,
    "client_assertion": token.serialize(),
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "code": httpd.authorization_response["code"][0],
    "code_verifier": httpd.code_verifier.decode("utf-8")
}
logging.debug(f'token_request_params = {body}')
logging.debug(f'token_request = {provider["token_endpoint"]}')
r = requests.post(provider["token_endpoint"], data=body)
token_response = r.json()
logging.debug(f'token_response = {token_response}')

# handles error from token response

if "error" in token_response:
    raise Exception(token_response["error"])

# id token, signed and encrypted

token = jwt.JWT(key=client_jwk_enc, jwt=token_response["id_token"])
token = jwt.JWT(key=provider_jwks, jwt=token.claims)
id_token = json.loads(token.claims)

# verify nonce

if httpd.nonce != id_token["nonce"]:
    raise Exception("invalid nonce")

logging.info(json.dumps(id_token, indent=2))
