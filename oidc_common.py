from base64 import urlsafe_b64encode
from hashlib import sha256
from jwcrypto import jwk, jwt
from typing import Any
import json
import logging
import os
import re
import requests
import uuid


def find_jwk_by_use(jwks: jwk.JWKSet, use: str) -> jwk.JWK:
    if jwks is None:
        return None
    jwk = None
    for k in jwks:
        t = k.export(private_key=False, as_dict=True)
        if "use" in t and t["use"] == use:
            return k
        if not "use" in t:
            jwk = k
    return jwk


global_state = dict()


class ClientState:
    def __init__(self, has_code_challenge: bool = True):
        self.state = str(uuid.uuid4())
        self.nonce = str(uuid.uuid4())
        # pkce
        if has_code_challenge:
            verifier = urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
            self.code_challenge = (
                urlsafe_b64encode(sha256(verifier).digest())
                .rstrip(b"=")
                .decode("utf-8")
            )
            self.code_verifier = verifier.decode("utf-8")
        else:
            self.code_challenge = None
            self.code_verifier = None
        global_state[self.state] = self


def get_client_state(authorization_response: dict) -> ClientState:
    s = authorization_response.get("state")
    if s is None:
        raise Exception("invalid state")
    state = global_state.get(s[0])
    if state is None:
        raise Exception("invalid state")
    return state


class OpenIDConfiguration:
    provider: Any = None
    provider_jwks: jwk.JWKSet = None
    provider_jwk_enc: jwk.JWK = None

    def __init__(self, openid_configuration: str):
        if re.match("^http(s)?:", openid_configuration):
            logging.debug(f"GET {openid_configuration}")
            r = requests.get(openid_configuration)
            r.raise_for_status()
            self.provider = r.json()
        else:
            logging.debug(f"read {openid_configuration}")
            with open(openid_configuration, "r", encoding="utf-8-sig") as fp:
                self.provider = json.loads(fp.read())
        if "jwks_uri" in self.provider:
            r = requests.get(self.provider["jwks_uri"])
            r.raise_for_status()
            self.provider_jwks = jwk.JWKSet.from_json(r.text)
            self.provider_jwk_enc = find_jwk_by_use(self.provider_jwks, "enc")

    @property
    def issuer(self):
        if "issuer" not in self.provider:
            raise Exception("missing issuer")
        return self.provider["issuer"]

    @property
    def authorization_endpoint(self):
        if "authorization_endpoint" not in self.provider:
            raise Exception("missing authorization_endpoint")
        return self.provider["authorization_endpoint"]

    @property
    def token_endpoint(self):
        if "token_endpoint" not in self.provider:
            raise Exception("missing token_endpoint")
        return self.provider["token_endpoint"]

    @property
    def userinfo_endpoint(self):
        if "userinfo_endpoint" not in self.provider:
            return None
        return self.provider["userinfo_endpoint"]

    def has_code_challenge_s256(self) -> bool:
        if "code_challenge_methods_supported" not in self.provider:
            return False
        return "S256" in self.provider["code_challenge_methods_supported"]


class ClientConfiguration:
    client: Any = None
    client_jwks: jwk.JWKSet = None
    client_jwk_sig: jwk.JWK = None
    scope: str = "openid"

    def __init__(
        self, client_configuration: str, client_jwks: str = None, scope: str = None
    ):
        logging.debug(f"read {client_configuration}")
        with open(client_configuration, "r", encoding="utf-8-sig") as fp:
            self.client = json.loads(fp.read())
        if client_jwks is not None:
            logging.debug(f"read {client_jwks}")
            with open(client_jwks, "r", encoding="utf-8-sig") as fp:
                self.client_jwks = jwk.JWKSet.from_json(fp.read())
                self.client_jwk_sig = find_jwk_by_use(self.client_jwks, "sig")
        if scope is not None:
            self.scope = scope
        elif "scope" in self.client:
            self.scope = self.client["scope"]
        else:
            self.scope = "openid"

    @property
    def client_id(self):
        if "client_id" not in self.client:
            raise Exception("missing client_id")
        return self.client["client_id"]

    @property
    def client_secret(self):
        if "client_secret" not in self.client:
            return None
        return self.client["client_secret"]

    @property
    def redirect_uri(self):
        if "redirect_uris" not in self.client:
            raise Exception("missing redirect_uris")
        return self.client["redirect_uris"][0]

    def has_code_challenge_s256(self) -> bool | None:
        if "code_challenge_method" not in self.client:
            return None
        if "S256" == self.client["code_challenge_method"]:
            return True
        return False

    def sign_request_object(self, provider, params):
        alg = "RS256"
        if "request_object_signing_alg" in self.client:
            alg = self.client["request_object_signing_alg"]
            if alg == "none":
                raise Exception("request_object_signing_alg is none")
            if alg is None:
                alg = "RS256"
        token = jwt.JWT(
            header={"alg": alg, "typ": "JWT", "kid": self.client_jwk_sig.kid},
            claims=params,
        )
        token.make_signed_token(self.client_jwk_sig)
        return token

    def encrypt_request_object(self, provider, token):
        if provider.provider_jwk_enc is None:
            return token
        alg = None
        if "request_object_encryption_alg" in self.client:
            alg = self.client["request_object_encryption_alg"]
            if alg == "none":
                alg = None
        enc = "A128GCM"
        if "request_object_encryption_enc" in self.client:
            enc = self.client["request_object_encryption_enc"]
            if enc == "none":
                enc = None
        if alg is None or enc is None:
            return token
        token = jwt.JWT(
            header={
                "alg": alg,
                "enc": enc,
                "cty": "JWT",
                "kid": provider.provider_jwk_enc.kid,
            },
            claims=token.serialize(),
        )
        token.make_encrypted_token(provider.provider_jwk_enc)
        return token

    def sign_client_assertion(self, provider, claims):
        alg = "RS256"
        if "token_endpoint_auth_signing_alg" in self.client:
            alg = self.client["token_endpoint_auth_signing_alg"]
            if alg == "none":
                raise Exception("token_endpoint_auth_signing_alg is none")
            if alg is None:
                alg = "RS256"
        token = jwt.JWT(
            header={"alg": alg, "typ": "JWT", "kid": self.client_jwk_sig.kid},
            claims=claims,
        )
        token.make_signed_token(self.client_jwk_sig)
        return token
