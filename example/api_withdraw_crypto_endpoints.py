#!/usr/bin/env python3

'''
A Python example program for withdraw by signing digest through C++ program.

Build the C++ program with the cpp-signer library.

    $ cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON -DCMAKE_BUILD_TYPE=Release -S. -Bbuild -DOPENSSL_ROOT_DIR=/usr/local && cmake --build build

Set the environments accordingly

    export BX_API_HOSTNAME=...
    export BX_PRIVATE_KEY=...
    export BX_API_METADATA=...

Run the Python example program

    $ ./build/example/api_withdraw_crypto_endpoints.py [withdraw body JSON string]

Example output

    ...
    $ ./build/example/api_withdraw_crypto_endpoints.py

    ***** LOGIN *******
    ...
    ***** WITHDRAWAL CHALLENGE *******
    ...
    ***** WITHDRAWAL ASSERTION *******
    ...
    JSON Response to Assertion: {'statusReason': 'Withdrawal assertion accepted', 'statusReasonCode': 1001, 'custodyTransactionId': 'DB:FW_6f15d9427f3b5a00c141faaa160584ae74db80bce0ae57cf7d856e9e57892174'}

'''

import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from hashlib import sha256

import requests
import subprocess


HOST_NAME = os.getenv("BX_API_HOSTNAME")
PRIVATE_KEY = os.getenv("BX_PRIVATE_KEY")
ENCODED_METADATA = os.getenv("BX_API_METADATA")

# C++ signer binary is in the same path as this python program
CPP_SIGNER = os.path.join(os.path.dirname(__file__), 'ecc_signing')


# Sign the digest with the C++ signer binary that calls the cpp-signer library
def sign_digest_with_cpp_lib(digest):
    global PRIVATE_KEY, CPP_SIGNER
    result = subprocess.run([CPP_SIGNER, PRIVATE_KEY, digest], stdout=subprocess.PIPE)
    signature = result.stdout.decode("utf-8").rstrip()
    return signature


# Example withdrawBody
withdrawBody = {
    "nonce" : "123578",
    "command" : {
        "commandType": "V1WithdrawalChallenge",
        "destinationId": "d8f79f38322c9de0b00b02bca20a307570a9d6f96179efee4068208b49f5ebd8",   #hash id
        "network": "SWIFT",
        "symbol": "USD",
        "quantity": "5"
    }
}

# if provided, use the argv[1] as the withdrawBody
if len(sys.argv) > 1:
    withdrawBody = sys.argv[1]


session = requests.Session()
metadata = base64.b64decode(ENCODED_METADATA)
print( f"MetaData: {metadata}")
account_id = str(json.loads(metadata)["accountId"])

PUBLIC_KEY = json.loads(metadata)["publicKey"]
print( f"Public Key: {PUBLIC_KEY}");

"""
LOGIN using standard Bullish trading-api mechanism
"""
print( "\n\n\n\n***** LOGIN *******\n")

timestamp = int(datetime.now(timezone.utc).timestamp())
expiration_time = int(timestamp + 300)
login_payload = {
    "accountId": account_id,
    "nonce": timestamp,
    "expirationTime": expiration_time,
    "biometricsUsed": False,
    "sessionKey": None,
}

payload = (json.dumps(login_payload, separators=(",", ":"))).encode("utf-8")
digest = sha256(payload.rstrip()).hexdigest()

signature = sign_digest_with_cpp_lib(digest)

print(f"Login digest: {digest}");
print(f"Login signature: {signature}");

headers = {
    "Content-type": "application/json"
}
body = {
    "publicKey": PUBLIC_KEY,
    "signature": signature,
    "loginPayload": login_payload,
}

print( f"body to be sent: {body}")

response = session.post(
    HOST_NAME + "/trading-api/v1/users/login",
    json=body,
    headers=headers,
    verify=True
)
print(f"HTTP Status: {response.status_code}")


responseJson = response.json()

print(f"JSON Response: {responseJson}")

print( "Token:")
print( f"{responseJson['token']}")

"""
Request a withdrawal challenge
"""

print( "\n\n\n\n***** WITHDRAWAL CHALLENGE *******\n")
# Attempt a withdrawal directly to ccqs on portforwarding
withdrawHeaders = {
  "Content-type": "application/json",
  "Authorization" : "Bearer " + responseJson['token']
}

print(f"About to send withdrawal challenge request to CCQS locally");

withdrawChallengeResponse = requests.Session().post(
    HOST_NAME+"/trading-api/v1/wallets/withdrawal-challenge",
    headers = withdrawHeaders,
    json=withdrawBody,
    verify=True
)

withdrawalJson = withdrawChallengeResponse.json();
print(f"JSON Response to Challenge Request: {withdrawalJson}")
challenge = withdrawalJson['challenge'];

print(challenge);

"""
Sign the challenge and send back to effect the withdrawal
"""
print( "\n\n\n\n***** WITHDRAWAL ASSERTION *******\n")

signature = sign_digest_with_cpp_lib(challenge)
print(signature);

withdrawAssertion = {
    "command" : {
        "commandType" : "V1WithdrawalAssertion",
        "signature": signature,
        "challenge": challenge,
        "publicKey": PUBLIC_KEY
    }
}

withdrawAssertionResponse = requests.Session().post(
    HOST_NAME+"/trading-api/v1/wallets/withdrawal-assertion",
    headers=withdrawHeaders,
    json=withdrawAssertion,
    verify=True
)

withdrawalAssertionResponseJson = withdrawAssertionResponse.json();
print( f"JSON Response to Assertion: {withdrawalAssertionResponseJson}");
