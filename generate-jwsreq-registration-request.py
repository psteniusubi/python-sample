from jwcrypto import jwk
from os.path import exists
import json
import uuid

# read or create jwsreq.jwk

jwks = None
if exists("code-flow-with-jwsreq.jwk"):
    with open("code-flow-with-jwsreq.jwk", "r", encoding="utf-8-sig") as fp:
        jwks = jwk.JWKSet.from_json(fp.read())
else:
    jwks = jwk.JWKSet()
    jwks.add(jwk.JWK(generate='RSA', use='sig', kid=str(uuid.uuid4())))
    jwks.add(jwk.JWK(generate='RSA', use='enc', kid=str(uuid.uuid4())))
    with open("code-flow-with-jwsreq.jwk", "w", encoding="utf-8") as fp:
        fp.write(jwks.export(private_keys=True))

# construct oauth/oidc client registration request, with following settings
# - signed and encrypted authorization request
# - jwt client authentication
# - signed and encrypted id token
# - signed and encrypted userinfo response

request = {
    "code_challenge_method":  "S256",
    "require_signed_request_object": True,
    "request_object_signing_alg": "RS256",
    "request_object_encryption_alg":  "RSA-OAEP",
    "token_endpoint_auth_method":  "private_key_jwt",
    "token_endpoint_auth_signing_alg": "RS256",
    "id_token_encrypted_response_alg":  "RSA-OAEP",
    "userinfo_signed_response_alg":  "RS256",
    "userinfo_encrypted_response_alg":  "RSA-OAEP",
    "redirect_uris":  [
        "http://localhost/redirect"
    ],
    "grant_types":  [
        "authorization_code"
    ],
    "scope": "openid",
    "jwks": jwks.export(private_keys=False, as_dict=True)
}

# write registration request on console
# - capture request and send to your indentity provider
# - write registration response to file named jwsreq.json

print(json.dumps(request, indent=2))
