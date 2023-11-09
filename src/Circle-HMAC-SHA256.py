# -*- coding: utf-8 -*-
import hashlib, hmac, json, os, sys, time
from datetime import datetime

# Keep secret parameters in environment
# circle_api_key = os.environ.get("CIRCLE_API_KEY")
circle_api_key = "NEW_API_KEY:7e3ad84e7046d3c9a42e57ac5e65024c:8******************************3"
key_type, key_id, key_secret = circle_api_key.split(':')


host = "api.circle.com"  # Hostname of circle api
APIService = "/v1/w3s"
CircleService = "/users/token"
endpoint = "https://" + host + APIService + CircleService

algorithm = "Circle-HMAC-SHA256"
timestamp = int(time.time())
date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

params = {"userId": "test_user"}  # Set your request parameters here

# ************* Step 1. Splicing request strings *************
http_request_method = "POST"

CircleQueryString = ""
ct = "application/json; charset=utf-8"
payload = json.dumps(params)
CircleHeaders = "content-type:%s\nhost:%s\n" % (ct, host)
signed_headers = "content-type;host"
hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()

CircleRequest = (http_request_method + "\n" +
                     CircleService+ "\n" +
                     CircleQueryString + "\n" +
                     CircleHeaders + "\n" +
                     signed_headers + "\n" +
                     hashed_request_payload)

print(f"CircleRequest:{CircleRequest}\n")

# ************* Step 2. Spell out signature strings *************
service = CircleService.replace("/", "")
credential_scope = date + "/" + service + "/" + "circle_request"

hashed_CircleRequest = hashlib.sha256(CircleRequest.encode("utf-8")).hexdigest()

string_to_sign = (algorithm + "\n" +
                  str(timestamp) + "\n" +
                  credential_scope + "\n" +
                  hashed_CircleRequest)
print(f"string_to_sign:{string_to_sign}\n")

# ************* Step 3. Calculate signing key *************

# Calculate the signature digest function
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

# sign by using key_secret according to Circle's API_KEY format
secret_date = sign(("Circle" + key_secret).encode("utf-8"), date)
secret_service = sign(secret_date, service)
secret_signing = sign(secret_service, "circle_request")
signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

print(f"signature:{signature}\n")

# ************* Step 4. Constructing the Authentication Header*************
authorization = (algorithm + " " +
                 "Credential=" + key_id + "/" + credential_scope + ", " +
                 "SignedHeaders=" + signed_headers + ", " +
                 "Signature=" + signature)
print(f"authorization:{authorization}\n")

# build curl command
print(f"""curl --request POST \\
     --url {endpoint} \\
     --header 'Authorization: {authorization}' \\
     --header 'Content-Type: application/json; charset=utf-8' \\
     --header 'Host: {host}' \\
     --data '
{payload}
'""")
