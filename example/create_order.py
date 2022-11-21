#!/usr/bin/env python3

import os
import sys
import json
from datetime import datetime, timezone
from hashlib import sha256
import subprocess
import requests

for envvar in ["BX_API_HOSTNAME", "BX_PRIVATE_KEY", "BX_JWT", "BX_AUTHORIZER"]:
    if os.getenv(envvar) is None:
        print("ERROR: required environment variable is not set: ", envvar)
        sys.exit(3)


HOST_NAME = os.getenv("BX_API_HOSTNAME")
PRIVATE_KEY = os.getenv("BX_PRIVATE_KEY")
JWT_TOKEN = os.getenv("BX_JWT")
AUTHORIZER = os.getenv("BX_AUTHORIZER")

# C++ signer binary is in the same path as this python program
CPP_SIGNER = os.path.join(os.path.dirname(__file__), 'ecc_signing')

session = requests.Session()
response = session.get(HOST_NAME + "/trading-api/v1/nonce", verify=False)
nonce = json.loads(response.text)["lowerBound"]
next_nonce = str(nonce + 1)
timestamp = str(int(datetime.now(timezone.utc).timestamp() * 1000))

body = {
    "timestamp": timestamp,
    "nonce": next_nonce,
    "authorizer": AUTHORIZER,
    "command": {
        "commandType": "V1CreateOrder",
        "handle": None,
        "symbol": "BTCUSD",
        "type": "LMT",
        "side": "BUY",
        "price": "30071.5000",
        "stopPrice": None,
        "quantity": "1.87000000",
        "timeInForce": "GTC",
        "allowMargin": False,
    },
}

payload = (json.dumps(body, separators=(",", ":"))).encode("utf-8")
digest = sha256(payload.rstrip()).hexdigest()

# 1st way:
# call the ecc_signing C++ program with sign with: private key, message digest
result = subprocess.run([CPP_SIGNER, PRIVATE_KEY, digest], stdout=subprocess.PIPE)

# 2nd way:
# result = subprocess.run([CPP_SIGNER, PRIVATE_KEY, payload.rstrip()], stdout=subprocess.PIPE)

cpp_signature = result.stdout.decode("utf-8").rstrip()

print("cpp_signature:", cpp_signature)

headers = {
    "Content-type": "application/json",
    "Authorization": f"Bearer {JWT_TOKEN}",
    "BX-SIGNATURE": cpp_signature,
    "BX-TIMESTAMP": timestamp,
    "BX-NONCE": next_nonce,
}

print("headers:", headers)
print("body:", body)

response = session.post(
    HOST_NAME + "/trading-api/v1/orders", json=body, headers=headers
)
print(f"HTTP Status: {response.status_code}, \n{response.text}")
