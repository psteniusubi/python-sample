from urllib.parse import urlencode
import requests
import webbrowser
import json
import uuid
from datetime import datetime, timedelta
from jwcrypto import jwt, jwe
from LoopbackServer import LoopbackServer
import logging
import argparse
from oidc_common import OpenIDConfiguration, ClientConfiguration
from input import start_input_thread
import sys

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

parser = argparse.ArgumentParser(description="OpenID Connect client")
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
        token = jwt.JWT(
            header={"alg": "RS256", "typ": "JWT", "kid": client.client_jwk_sig.kid},
            claims=params,
        )
        token.make_signed_token(client.client_jwk_sig)

        # request object - encrypt
        if provider.provider_jwk_enc is not None:
            token = jwt.JWT(
                header={
                    "alg": "RSA-OAEP",
                    "enc": "A128GCM",
                    "cty": "JWT",
                    "kid": provider.provider_jwk_enc.kid,
                },
                claims=token.serialize(),
            )
            token.make_encrypted_token(provider.provider_jwk_enc)

        return {
            "request": token.serialize(),
            "response_type": params["response_type"],
            "client_id": params["client_id"],
            "scope": params["scope"],
        }


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

if httpd.state != httpd.authorization_response["state"][0]:
    raise Exception("invalid state")

# client assertion, signed

claims = {
    "iss": client.client_id,
    "sub": client.client_id,
    "aud": (provider.issuer, provider.token_endpoint),
    "exp": int((datetime.now() + timedelta(minutes=10)).timestamp()),
    "jti": str(uuid.uuid4()),
}
logging.debug(f"client_assertion_claims = {claims}")
token = jwt.JWT(
    header={"alg": "RS256", "typ": "JWT", "kid": client.client_jwk_sig.kid},
    claims=claims,
)
token.make_signed_token(client.client_jwk_sig)

# token request with authorization code and client assertion

body = {
    "client_id": client.client_id,
    "grant_type": "authorization_code",
    "redirect_uri": httpd.redirect_uri,
    "client_assertion": token.serialize(),
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "code": httpd.authorization_response["code"][0],
    "code_verifier": httpd.code_verifier.decode("utf-8"),
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

if httpd.nonce != id_token["nonce"]:
    raise Exception("invalid nonce")

logging.info(json.dumps(id_token, indent=2))
