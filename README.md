# OpenID Connect with Python

## Introduction

This repository contains two Python sample scripts for OpenID Connect integration. Both scripts implement [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) with [Loopback Redirection](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3). 

* [code-flow.py](code-flow.py) implements most simple code flow sequence without any JWT cryptograhic operations. It first runs basic code flow, then fetches claims from userinfo endpoint.
* [code-flow-with-jwsreq.py](code-flow-with-jwsreq.py) is more advanced with [JWT-secured authorization request](https://datatracker.ietf.org/doc/html/rfc9101), [JWT client authentication](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2) and [encrypted ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

### Scope

This application shows how to get an access token using authorization code flow from a "native app" such as a command line tool. This is not a traditional web application with a browser based ui.

There are a number of existing OpenID Connect libraries and tools for Python that could be used to achieve what this application does. However my intent is to show how OpenID Connect works more than showing how to use a particular library. 

### Dependencies

Run the following command before running this application to make sure required dependencies are installed 

```text
pip install requests jwcrypto 
```

# code-flow.py

## Configuration

Configuration of this script is simple. You can use any localhost address with a path component as redirect uri, for example http://localhost/redirect. When you register this app, your OpenID Provider will return client id and secret. Put these parameters into [code-flow.json](code-flow.json). If you specify a port number with the localhost address, the loopback redirect server will bind to that specific port, otherwise any available (random) port on that address will be used.

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

Specify your OpenID Provider's configuration metadata address on the command line

```
python code-flow.py --openid-configuration https://login.example.ubidemo.com/uas/.well-known/openid-configuration
```

## Code review

### LoopbackServer.py

TODO

### code-flow.py

TODO

## Launching

The configuration in [code-flow.json](code-flow.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```
python code-flow.py
```

# code-flow-with-jwsreq.py

## Configuration

### Generate new key pair and configuration request

Run [generate-jwsreq-registration-request.py](generate-jwsreq-registration-request.py) to generate a new key pair and configuration request.

```
python generate-jwsreq-registration-request.py --new
```

The command will output a configuration request that you can send to your OpenID Provider. The configuration request contains settings to enable JWT secured request, JWT client authentication and encrypted ID token. If your OpenID Provider does not accept configuration request then you need to make sure the provider is configured with these features enabled. 

A sample configuration request

```json
{
  "code_challenge_method": "S256",
  "require_signed_request_object": true,
  "request_object_signing_alg": "RS256",
  "request_object_encryption_alg": "RSA-OAEP",
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",
  "id_token_signed_response_alg": "RS256",
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

If your OpenID Provider returns a configuration response then put this into file [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json). 

If not then create configuration response manually with the client id from your OpenID Provider.

Sample configuration response from OpenID Provider. Put this into [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json)

```json
{
    "redirect_uris":  [
                          "http://localhost/redirect"
                      ],
    "client_id":  "69ec4f7e-07f7-426d-a560-55fd8969caac"
}
```

Specify your OpenID Provider's configuration metadata address on the command line

```
python code-flow-with-jwsreq.py --openid-configuration https://login.example.ubidemo.com/uas/.well-known/openid-configuration
```

## Code review

### code-flow-with-jwsreq.py

TODO

## Launching

The configuration in [code-flow-with-jwsreq.jwk](code-flow-with-jwsreq.jwk) and [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```
python code-flow-with-jwsreq.py
```
