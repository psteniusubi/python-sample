from urllib.parse import urlencode
import requests
import webbrowser
import json
import uuid
from datetime import datetime, timedelta
from jwcrypto import jwt, jwk
from LoopbackServer import LoopbackServer
import logging

# logging

logging.basicConfig(level=logging.INFO)

# provider discovery

r = requests.get(
    "https://login.example.ubidemo.com/uas/.well-known/openid-configuration")
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

with open("code-flow-with-jwsreq.json", "r", encoding="utf-8-sig") as fp:
    client = json.loads(fp.read())

with open("code-flow-with-jwsreq.jwk", "r", encoding="utf-8-sig") as fp:
    client_jwks = jwk.JWKSet.from_json(fp.read())

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
        params["sub"] = self.client["client_id"]
        params["aud"] = (self.provider["issuer"], self.provider["token_endpoint"],
                         self.provider["authorization_endpoint"])
        params["exp"] = int(
            (datetime.now() + timedelta(minutes=10)).timestamp())
        params["jti"] = str(uuid.uuid4())
        # request object, signed and encrypted
        token = jwt.JWT(header={"alg": "RS256", "typ": "JWT",
                        "kid": client_jwk_sig.key_id}, claims=params)
        token.make_signed_token(client_jwk_sig)
        token = jwt.JWT(header={"alg": "RSA-OAEP", "enc": "A128GCM", "cty": "JWT",
                        "kid": provider_jwk_enc.key_id}, claims=token.serialize())
        token.make_encrypted_token(provider_jwk_enc)
        return {
            "request": token.serialize()
        }

# create and start http server


with JwsreqServer(provider, client) as httpd:
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
token = jwt.JWT(header={"alg": "RS256", "typ": "JWT",
                "kid": client_jwk_sig.key_id}, claims=claims)
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
r = requests.post(provider["token_endpoint"], data=body)
token_response = r.json()

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

print(json.dumps(id_token, indent=2))
