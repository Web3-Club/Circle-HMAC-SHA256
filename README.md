# API Security Hardening Solution based on Circle Programmable Wallet
## introductory

The Web3 project is at the forefront of fintech innovation in the rapidly evolving world of digital currencies and decentralized finance.

Web3, as a form of application of blockchain technology, is centered on building a decentralized network and application ecosystem, in which digital wallets play a crucial role. Digital wallets are not only the medium for users to conduct digital currency transactions, but also the gatekeeper of their personal property security. With the accelerated pace of asset digitization transformation, the wallet holds not only transaction rights, but also extends to identity authentication, asset management and other fields. Therefore, its security is directly related to the stability and trust of the entire Web3 financial ecosystem.

In the current Web3 financial project, we can see a series of complex financial operations realized through smart contracts. The execution of all these operations in Circle relies on the APIs connected to the digital wallet, and the security of the APIs becomes the first line of defense to ensure the safety of funds, maintain user trust, and prevent hacker attacks.

Circle programmable wallet has powerful functions and flexible programmable features, and it is believed that it can be widely used in the market. However, before its popularity increases, it is indispensable to regulate its security, especially the management and protection of API keys, which has become a key issue that we need to solve urgently.

In response to this background, we have initiated this project with the aim of enhancing the security of the entire Web3 Finance project by building a security hardening solution for the Circle programmable wallet's API keys. Our goal is to ensure that every aspect of the API key lifecycle, including generation, storage, usage and revocation, meets the highest security standards through the latest security technologies and best practices, so as to ensure the security of user assets and the long-term sustainability of the project.

## Circle Wallet API Overview

### Overview of Circle API security mechanisms

#### Reference：https://developers.circle.com/w3s/reference/

The focus here is on the authentication parameters involved in the API.

By reading the official API documentation, we can see that Circle's API uses the **API Key** placed in the header as the **only** authentication credentials for some operations.

```shell
  curl --request Method \
  --url APIurl \
  --header 'Authorization: Bearer <YOUR_API_KEY>' \

```

For both developer-controlled wallets and user-controlled wallets, there are two separate sets of authentication:

For **users**, all upstream sensitive operations, such as transactions, are **"transfers"**, i.e., **queries**, which require additional confirmation using a **PIN** on the app.

For **developers**, all sensitive operations need to use an **independently generated 32-bit entity key** computed using **entitySecretCiphertext**.

![mind map](https://picdm.sunbangyan.cn/2023/11/09/146bfa9fc1c3d44732a77004380a61c5.png)


+ All APIs are delivered based on the HTTPS protocol.

+ The API has basic permissions management with IP AllowList whitelist validation.

+ PIN code processing is based on SDK, which is built on Wrapper and is not open source, ensuring that developers do not have direct access to the user's PIN code.

+ **entitySecretCiphertext** is based on **independently generated 32-bit entity keys**, and the generation of **entitySecretCiphertext** uses the PKCS1_OEAP random padding scheme, which makes even the same piece of data encrypted every time the result will be different, greatly reducing the risk of being attacked by plaintext.

+ According to the EU General Data Protection Regulation (GDPR) all transactions and API calls are logged, but this is routine and nothing to mention.

### Security risk analysis

#### API_KEY

Although API_KEY, and API are based on HTTPS protocol transmission, but API_KEY does appear in the transmission process, HTTPS is indeed secure enough, but as a financial application of Web3, the data security is all pressed on HTTPS, is not a very recognized behavior.

So for API_KEY, the reinforcement we did is to let him only appear as a part of the calculation, not reflected in the transmission process.

The permissions of APIKEY, although there is authority control, but it is not very fine, so overall, the use of signatures instead of direct transmission is very necessary.

The current API_KEY format is as follows:

```python
TEST_API_KEY:7******************************c:8******************************3
{KEY_TYPE}:{KEY_ID}:{KEY_secret}
```

Signatures help protect requests in the following ways:

+ Verifying the identity of the requestor

     Signing ensures that the request is sent by someone with a valid access key.

+ Protecting Data in Transit

     To prevent requests from being tampered with in transit, the API uses the request parameters to calculate a hash of the request and encrypts the resulting hash as part of the request, sending it to the API server.
     The server uses the received request parameters to compute the hash value using the same process and verifies the hash value in the request. If the request is tampered with, this will result in an inconsistent hash value and the Center API will reject the request.

### Reinforcement strategy design

#### Circle-HMAC-SHA256 Signature

##### Public Parameters

Public parameters are parameters used to identify the user and interface signatures that need to be carried in each request in order to initiate the request properly.

**Timestamp**

Former UNIX timestamp, accurate to the second. Note that all timestamps should be the same for each request.

**Authorization**

The value of the HTTP Standard Authentication header field, Circle-HMAC-SHA256.

##### Splicing request strings

```
CircleRequest =
    HTTPRequestMethod + '\n' +
    CircleService + '\n' +
    CircleQueryString + '\n' +
    CircleHeaders + '\n' +
    SignedHeaders + '\n' +
    HashedRequestPayload
```

##### Request Method:

`HTTPRequestMethod`: the method type of the request, such as `GET` or `POST`.

##### Request Service:

`CircleService`: the specific service requested, for Circle API e.g. for API `https://api.circle.com/v1/w3s/users/token` is `/users/token`

##### Query String:

`CircleQueryString`: empty for `POST` requests, contains the query parameter in the URL for `GET` requests, e.g. `?pageSize=10`.

##### Header information:
`CircleHeaders`：The headers to be included in the signature should contain at least the `host` and `content-type` headers, and other headers may be included to increase the uniqueness and security of your request.

Splicing rules：

The header key and value are converted to lowercase, the first and last spaces are removed, and they are spliced according to the `key:value\n` format;

Multiple headers are spliced in ascending ASCII order of the header key (lowercase).

##### signature header:
`SignedHeaders`：The name of the header field of the participating signatures, e.g. `content-type;host;`.

##### hash of the requested load:
`HashedRequestPayload`: for `POST` requests, it is the SHA256 hash of the request body; for `GET` requests, it is usually the empty string.

Calculation method: `Lowercase(HexEncode(Hash.SHA256(RequestPayload)))`

#### Spell out signature strings

```
StringToSign =
    "Circle-HMAC-SHA256" + '\n' +
    RequestTimestamp + '\n' +
    CredentialScope + '\n' +
    SHA256(CircleRequest)
```

##### "Circle-HMAC-SHA256":

This part is a constant indicating that Circle's customized HMAC-SHA256 signature algorithm is used.

##### RequestTimestamp:

This is the timestamp of the time when the API request was sent. It takes the current time UNIX timestamp, to the nearest second, taking care to keep it consistent with the timestamp in the request header.

##### CredentialScope:
This part defines the valid range of the signature, which usually contains the date of the request, the target service, and a fixed string (in this case "circle_request") that binds the signature to a specific service and date. The format is usually `YYYY-MM-DD/Service/circle_request`.

+ `YYYY-MM-DD` is the date of the request, which must match the date in `RequestTimestamp`.

+ `Service` is the name of the Circle API service you are requesting, e.g. for API "https://api.circle.com/v1/w3s/users/token" is `usertoken`.

+ `circle_request` termination string.

##### SHA256(CircleRequest):
This is the SHA256 hash of the `CircleRequest` string.

The `CircleRequest` includes hash values for the HTTP request method, request service, query string, header information, signature header, and request payload.

Calculating the hash value from this information ensures that the request has not been modified in transit and that the signature is only valid for this particular request.

#### Calculate Signing Key
For API_KEY : **{KEY_TYPE}:{KEY_ID}:{KEY_secret}**

Calculate `SecretDate` from API_KEY and `Date` using `KEY_secret`:

``` JavaScript
SecretDate = HMAC_SHA256("Circle" + KEY_secret, Date) 
```

Compute `SecretService` using `SecretDate` and the service name:

```SCSS
SecretService = HMAC_SHA256(SecretDate, Service) 
```

Calculate `SecretSigning` using `SecretService`:

```Makefile
SecretSigning = HMAC_SHA256(SecretService, "circle_request") 
```

#### Calculated Signature

```Makefile 
Signature = HexEncode(HMAC_SHA256(SecretSigning, StringToSign))
```

#### Constructing the Authentication Header
```SCSS
Authorization =
    "Circle-HMAC-SHA256" + ' ' +
    "Credential=" + KEY_ID + '/' + CredentialScope + ', ' +
    "SignedHeaders=" + SignedHeaders + ', ' +
    "Signature=" + Signature
```
- Use the `Authorization` header to add to the HTTP request header information when initiating an API request.

This signature specification requires the sender to provide a signature computed from the `KEY_secret` when initiating a request, and the receiver (the Circle API server) can verify the validity of the signature using the same algorithm and the sender's `KEY_ID`. This ensures the integrity and authentication of the request while avoiding direct transmission of the `KEY_secret`.

#### final result
The API object requested by `APIService`, for the Circle API e.g. for the API https://api.circle.com/v1/w3s/users/token is /v1/w3s.

Access url is `host` + `APIService` + `CircleService`

```Python
curl --request POST \
     --url Host+APIService+CircleService \
     --header 'Timestamp' \
     --header 'Authorization' \
     --header 'content-type: application/json' \
     --data '{"userId": "test_user"}'
```

#### example

For example, creating users.

```Python
curl --request POST \
     --url https://api.circle.com/v1/w3s/users \
     --header 'accept: application/json' \
     --header 'authorization: Bearer TEST_API_KEY:7e3ad84e7046d3c9a42e57ac5e65024c:88ab0846284532c3bab2a6d37974efd3' \
     --header 'content-type: application/json' \
     --data '
{
  "userId": "test_user"
}
'
```

Under that signature verification:

```python
curl --request POST \
     --url https://api.circle.com/v1/w3s/users/token \
     --header 'Authorization: Circle-HMAC-SHA256 Credential=7e3ad84e7046d3c9a42e57ac5e65024c/2023-11-09/userstoken/circle_request, SignedHeaders=content-type;host, Signature=ae2684e8b60f1a15f25da453ff5f4309176338f8926bfa7d420a7b4e5cb5cfd7' \
     --header 'Content-Type: application/json; charset=utf-8' \
     --header 'Host: api.circle.com' \
     --data '
{"userId": "test_user"}
'
```

#### Code:

```Python
# -*- coding: utf-8 -*-
import hashlib, hmac, json, os, sys, time
from datetime import datetime

# Key parameters Recommended environment variables
# circle_api_key = os.environ.get("CIRCLE_API_KEY")
circle_api_key = "NEW_API_KEY:7e3ad84e7046d3c9a42e57ac5e65024c:8******************************3"
key_type, key_id, key_secret = circle_api_key.split(':')

host = "api.circle.com" # hostname of the Circle API 
APIService = "/v1/w3s"
CircleService = "/users/token"
endpoint = "https://" + host + APIService + CircleService

algorithm = "Circle-HMAC-SHA256"
timestamp = int(time.time())
date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")

params = {"key3": "value3", "key4": "value4"}  # Set the parameters according to the actual API call

# ************* Step 1: Splicing the canonical request string *************
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

# ************* Step 2: Spell out the signature string *************
service = CircleService.replace("/", "")
credential_scope = date + "/" + service + "/" + "circle_request"

hashed_CircleRequest = hashlib.sha256(CircleRequest.encode("utf-8")).hexdigest()

string_to_sign = (algorithm + "\n" +
                  str(timestamp) + "\n" +
                  credential_scope + "\n" +
                  hashed_CircleRequest)
print(f"string_to_sign:{string_to_sign}\n")

# ************* Step 3: Calculation of signatures *************

# Compute Signature Digest Function
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

# According to Circle's API_KEY format, the key_secret part of the signature is used here
secret_date = sign(("Circle" + key_secret).encode("utf-8"), date)
secret_service = sign(secret_date, service)
secret_signing = sign(secret_service, "circle_request")
signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
print(signature)

# ************* Step 4: Splice Authorization *************
authorization = (algorithm + " " +
                 "Credential=" + key_id + "/" + credential_scope + ", " +
                 "SignedHeaders=" + signed_headers + ", " +
                 "Signature=" + signature)
# print(authorization)

# Build Curl Command
print('curl --request POST ' + endpoint
      +
      + ' -H "Authorization: ' + authorization + '"'
      + ' -H "Content-Type: application/json; charset=utf-8"'
      + ' -H "Host: ' + host + '"'
      + ' -d \'' + payload + '\'')
```
