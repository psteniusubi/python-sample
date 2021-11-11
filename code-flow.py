import requests
import webbrowser
from LoopbackServer import LoopbackServer
import json
import logging

# logging

logging.basicConfig(level=logging.INFO)

# provider discovery

r = requests.get(
    "https://login.example.ubidemo.com/uas/.well-known/openid-configuration")
r.raise_for_status()
provider = r.json()

# client configuration 

with open("code-flow.json", "r", encoding="utf-8-sig") as fp:
    client = json.loads(fp.read())

# create and start http server

with LoopbackServer(provider, client) as httpd:
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
print(json.dumps(r.json(), indent=2))

# (optional) invoke sso management api with access token

headers = {
    "Accept": "application/json",
    "Authorization": "Bearer " + token_response["access_token"]
}
r = requests.get(
    "https://manage.example.ubidemo.com/sso-api/site", headers=headers)
r.raise_for_status()
print(json.dumps(r.json(), indent=2))
