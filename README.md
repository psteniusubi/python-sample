# OpenID Connect with Python

## Introduction

This repository contains two Python sample scripts for OpenID Connect integration. Both scripts implement [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) with [Loopback Redirection](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3). 

* [code-flow.py](code-flow.py) implements most simple code flow sequence without any JWT cryptograhic operations. It first runs code flow sequence, the fetches claims from the userinfo endpoint.
* [code-flow-with-jwsreq.py](code-flow-with-jwsreq.py) is more advanced with [JWT-secured authorization request](https://datatracker.ietf.org/doc/html/rfc9101), [JWT client authentication](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2) and [encrypted ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

# code-flow.py

## Configuration

## Code review

## Launching

The configuration in [code-flow.json](code-flow.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```text
python code-flow.py
```

# code-flow-with-jwsreq.py

## Configuration

## Code review

## Launching

The configuration in [code-flow-with-jwsreq.jwk](code-flow-with-jwsreq.jwk) and [code-flow-with-jwsreq.json](code-flow-with-jwsreq.json) is ready configured to access Ubisecure SSO at login.example.ubidemo.com

```text
python code-flow-with-jwsreq.py
```
