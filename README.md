# OpenID Connect with Python

## Introduction

This repository contains two Python sample scripts for OpenID Connect integration. Both scripts implement [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) with [Loopback Redirection](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3). 

* [code-flow.py](code-flow.py) implements most simple code flow sequence without any JWT cryptograhic operations. It first runs basic code flow, then fetches claims from userinfo endpoint.
* [code-flow-with-jwsreq.py](code-flow-with-jwsreq.py) is more advanced with [JWT-secured authorization request](https://datatracker.ietf.org/doc/html/rfc9101), [JWT client authentication](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2) and [encrypted ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

# code-flow.py

## Configuration

Configuration of this script is simple. You can use any localhost address with a path component as redirect uri, for example http://localhost/redirect. When you register this app, your OpenID Provider will return client id and secret. Put these parameters into [code-flow.json](code-flow.json)

Sample configuration request

```json
{
    "redirect_uris":  [
                          "http://localhost/redirect"
                      ]
}
```

Sample configuration response from OpenID Provider. Put this into [code-flow.json](code-flow.json)

```json
{
    "redirect_uris":  [
                          "http://localhost/redirect"
                      ],
    "client_id":  "2734e56f-d637-4908-b354-6be497ffed76",
    "client_secret":  "qdiA0CTxU3dNdH6e"
}
```

In [code-flow.py](code-flow.py#L14) replace address with your OpenID Provider's configuration metadata address.

```py
r = requests.get(
    "https://login.example.ubidemo.com/uas/.well-known/openid-configuration")
```

## Code review

### LoopbackServer.py

TODO

### code-flow.py

TODO

## Launching

The configuration in [code-flow.json](code-flow.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```text
python code-flow.py
```

# code-flow-with-jwsreq.py

## Configuration

### Generate new key pair and configuration request

To generate new key pair remove the file [code-flow-with-jwsreq.jwk](code-flow-with-jwsreq.jwk). Then run [generate-jwsreq-registration-request.py](generate-jwsreq-registration-request.py).

```text
python generate-jwsreq-registration-request.py 
```

The command will output a configuration request that you can send to your OpenID Provider, for example

```json
{
  "code_challenge_method": "S256",
  "require_signed_request_object": true,
  "request_object_signing_alg": "RS256",
  "request_object_encryption_alg": "RSA-OAEP",
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",
  "id_token_encrypted_response_alg": "RSA-OAEP",
  "userinfo_signed_response_alg": "RS256",
  "userinfo_encrypted_response_alg": "RSA-OAEP",
  "redirect_uris": [
    "http://localhost/redirect"
  ],
  "grant_types": [
    "authorization_code"
  ],
  "scope": "openid",
  "jwks": {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "kid": "ca4a56c3-0ed9-4c04-a055-b5036264645e",
        "n": "yyTZk2Fx4Rx0ahUEbnTV3PcP6jkhGJ7KIOaE8vaVbYxYuOYNIqmi7ll3zDgxt_bzHiEZgcVI_7pgTHjGG2NNyw1nptYy2D72dwuHb6xQHzHhmk3d-Kd3Ot95rmP_t-pFOSm3kxeoJgp_cpXN5bLAu58UcVd-uEhtRcKp6aWU2Cm3SCxHWuAZfoF8pVyAfmjQpTyInzYq5HYPWbOvnw4FOGgwHdDxh9baP0l1xqoeYVnpIKgAKF4abmypw2vZkPg4dpDH0-OAZH2tVcYC_QwFgkatjDwK-VjGE1eNiEXqRFCoMhiKE0KUPJIaCDhyb0aTe9uHtJKW8O8jktFFvoEErw",
        "e": "AQAB"
      },
      {
        "kty": "RSA",
        "use": "enc",
        "kid": "e9234e3e-7433-4ef5-ac74-21e84e453d71",
        "n": "6JW0ZyRvJyN_xChDPDih3fpiFWks0hIeq_eTeCVSmYLZco4DEYqYogDSWwE2G0RKk7VA1_YNT4uGzrR9nJYnLDXqa3ml3eeRTpF8qCYCH4RGVnKKh7LfvZ9vwrY_W7rb9tW9d-yygrFlhujwoMi4hj1tyA4vm0WkQ-xRYwXIc8DdcEQvPmXrQRDIOko82umOntPvFzHzBmv5H6nkhMf8eBvhj8xGaKwJUYY_Igi7AyFryD3v_JkzP0AtkAapjnz7Rw95hijCBGkrCq--FHeHQoSKwTCTvbaM2K5YARvYORY-d_w6kiqglFxQREnoB7AEB_Jwi6QQYbbCBLVAqXrzOw",
        "e": "AQAB"
      }
    ]
  }
}
```

### Update configuration

When you register this app, your OpenID Provider will return a client id. A client secret is not necessary as this client uses asymmetric keys for authentication.

If your OpenID Provider returns a configuration response then write it to file [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json). If not then create configuration response manually by adding client_id parameter to configuration request.

Finally, in [code-flow.py](code-flow.py#L14) replace address with your OpenID Provider's configuration metadata address.

```py
r = requests.get(
    "https://login.example.ubidemo.com/uas/.well-known/openid-configuration")
```

## Code review

### code-flow-with-jwsreq.py

TODO

## Launching

The configuration in [code-flow-with-jwsreq.jwk](code-flow-with-jwsreq.jwk) and [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```text
python code-flow-with-jwsreq.py
```
