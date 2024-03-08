from typing import Any
import logging
import requests
import json
import re
from jwcrypto import jwk


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
