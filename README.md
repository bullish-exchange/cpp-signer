# C++ library and examples for signing messages or digests using R1 keys

This repo provides the library and minimal C++ code example to sign any arbitrary message with an EOSIO R1 key and produce an EOSIO signature (k1 keys are not yet supported).

## Build the library

Make sure the OpenSSL is install (please check the section below) the submodules are pulled before compiling it.

```
git submodule update --init --recursive
```

To build the project, and run the unit tests:

```
mkdir -p build
cd build
# -DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON can enable more examples which require the compiler to support C++17
cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/usr/local ..
make -j8

ctest
```

### Example Dockerfile

We provide example Dockerfiles for references:

```
docker build --progress=plain -t cpp-signer-centos7 -f ./centos7.dockerfile .
```

```
docker build --progress=plain -t cpp-signer-centos8 -f ./centos8.dockerfile .
```

The building process will build the library and the unit test, and run the unit test program.

## How to - integration into your own project

In your CMakeLists.txt

```
include(FetchContent)
cmake_minimum_required (VERSION 3.10)
project(
  use_eosio_r1_key
  VERSION 1.0
  LANGUAGES CXX)

add_subdirectory(cpp-signer)

add_executable(mysrc mysrc.cpp)
target_link_libraries(mysrc PRIVATE eosio_r1_key)
```

In your C++ source code `mysrc.cpp`
```
#include <eosio/r1_key.hpp>
#include <iostream>

int main() {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
  const char* test_json = R"x({"accountId":"abc","nonce":1,"expirationTime":1636755051,"biometricsUsed":false,"sessionKey":null})x";

  // The private key in this example is coded into the source. In production settings please store the private key in an environment variable and retrieve it here
  eosio::r1::private_key priv_key{"PVT_R1_iyQmnyPEGvFd8uffnk152WC2WryBjgTrg22fXQryuGL9mU6qW"};

  std::cout << priv_key.sign(test_json)<< "\n";

  return 0;
}
```

## Example programs

Here are some example programs using this library.

Note: to build the example program, the `-DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON` option is need to `cmake` to enable them, and these example program building requires the compiler to support C++17.

### Call the Withdraw API

This repo provides an example C++ program using the cpp-signer library to sign requests to perform withdraw Custody API calls.

Note: the withdrawal request body contains a hash ID. For different testing accounts, please use the corresponding hash IDs for the destinations.

To run the build program:

```
# Set the environments accordingly, following https://github.com/bullish-exchange/api-examples

export BX_API_HOSTNAME=...
export BX_PRIVATE_KEY=...
export BX_API_METADATA=...
```

Run the `withdraw` program to place the withdraw request:

```
./build/example/withdraw
```

One example output:

```
=== STEP 0. Load Environment Variables =============================================================

% Loaded BX_API_HOSTNAME: https://api.simnext.bullish-test.com
% Loaded BX_PRIVATE_KEY: *********************************************************
% Loaded BX_API_METADATA: eyJhY2NvdW50SWQiOiIyMjIwMDAwMDAwMDAwMDUiLCJwdWJsaWNLZXkiOiJQVUJfUjFfN2M1V1ljUTZhU1hGVHdUVXRNY0VYRmpadGJqYkR1bUNlTnI3b1lEU0JGN3h1cXBEVjMiLCJjcmVkZW50aWFsSWQiOiIyMDI4OCJ9
{"accountId":"222000000000005","publicKey":"PUB_R1_7c5WYcQ6aSXFTwTUtMcEXFjZtbjbDumCeNr7oYDSBF7xuqpDV3","credentialId":"20288"}
% Loaded from BX_API_METADATA accountId: 222000000000005
% Loaded from BX_API_METADATA publicKey: PUB_R1_7c5WYcQ6aSXFTwTUtMcEXFjZtbjbDumCeNr7oYDSBF7xuqpDV3
% Loaded from BX_API_METADATA credentialId: 20288

=== STEP 1. Login ==================================================================================

% signature: SIG_R1_K1kzQoXg7HJ84fXZFwogNQ3bsrDrerZDM7wV3vsLtEWJAZ2UNxReM9tyZ7MKEG64cevdCbD26C3oqJVLV9ACKM3HMTh2pq
% Sending HTTP request to: https://api.simnext.bullish-test.com/trading-api/v1/users/login
% Sending HTTP request with body: {"publicKey":"PUB_R1_7c5WYcQ6aSXFTwTUtMcEXFjZtbjbDumCeNr7oYDSBF7xuqpDV3","signature":"SIG_R1_K1kzQoXg7HJ84fXZFwogNQ3bsrDrerZDM7wV3vsLtEWJAZ2UNxReM9tyZ7MKEG64cevdCbD26C3oqJVLV9ACKM3HMTh2pq","loginPayload":{"accountId":"222000000000005","nonce":1669880212,"expirationTime":1669880512,"biometricsUsed":false,"sessionKey":null}}
% Received HTTP response status code: 200
% Received HTTP response body: {"authorizer":"05E02367E8C90000404F000000000000","ownerAuthorizer":"05E02367E8C90000404F000000000000","token":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJiMXgtYXV0aC1zZXJ2aWNlIiwic3ViIjoiMjI0MDUyMCIsImV4cCI6MTY2OTk2NjYxMiwiU1RBR0UiOiJBVVRIRU5USUNBVEVEX1dJVEhfQkxPQ0tDSEFJTiJ9._oFi1NpjCUkrPSYj9AcZQ6RLs4P8Bjr5CComLEh4hptThP46CW-Mf8H_LdrU_Ws0DNJ4lXUfOV12R_LDt2TuzQ","rateLimitToken":"518f8eaa9cfe932ede458499b25612b56828c171c1b864dca4fa3706185d2a77"}
% Token: eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJiMXgtYXV0aC1zZXJ2aWNlIiwic3ViIjoiMjI0MDUyMCIsImV4cCI6MTY2OTk2NjYxMiwiU1RBR0UiOiJBVVRIRU5USUNBVEVEX1dJVEhfQkxPQ0tDSEFJTiJ9._oFi1NpjCUkrPSYj9AcZQ6RLs4P8Bjr5CComLEh4hptThP46CW-Mf8H_LdrU_Ws0DNJ4lXUfOV12R_LDt2TuzQ

=== STEP 2. Withdrawal Challenge ===================================================================

% Sending HTTP request to: https://api.simnext.bullish-test.com/trading-api/v1/wallets/withdrawal-challenge
% Sending HTTP request with body: {"nonce":"1669880212","command":{"commandType":"V1WithdrawalChallenge","destinationId":"bf6d41a97a1d56e289cdaf10f386a3bd5166d51f9edf50892874bf2e7c0ddaf4","network":"SWIFT","symbol":"USD","quantity":"1"}}
% Received HTTP response status code: 200
% Received HTTP response body: {"challenge":"755b8c0a147f2b3735d7c90869d5cf2d41025aa20b245671bcf3098e071e06a2","custodyTransactionId":"DB:FW_0c4c220c545ed1c0f54c918b2141c79f23ea866f64853c805b27b9f1fd61a6c2","statusReason":"Withdrawal challenge created","statusReasonCode":1001}
% Challenge: 755b8c0a147f2b3735d7c90869d5cf2d41025aa20b245671bcf3098e071e06a2

=== STEP 3. Withdrawal Assertion ===================================================================

% Signature: SIG_R1_KBf2suQydKkfNBBR5jmtYjUo2KKXtp8kYuV1TPGrs31LnnwBT7CJtt7HPmdUDExRaAtBYYFiqacW7zvF3sffTPuti8r4wA
% Sending HTTP request to https://api.simnext.bullish-test.com/trading-api/v1/wallets/withdrawal-assertion
% Sending HTTP request with body: {"command":{"commandType":"V1WithdrawalAssertion","signature":"SIG_R1_KBf2suQydKkfNBBR5jmtYjUo2KKXtp8kYuV1TPGrs31LnnwBT7CJtt7HPmdUDExRaAtBYYFiqacW7zvF3sffTPuti8r4wA","challenge":"755b8c0a147f2b3735d7c90869d5cf2d41025aa20b245671bcf3098e071e06a2","publicKey":"PUB_R1_7c5WYcQ6aSXFTwTUtMcEXFjZtbjbDumCeNr7oYDSBF7xuqpDV3"}}
% Received HTTP response status code: 200
% Received HTTP response body: {"statusReason":"Withdrawal assertion accepted","statusReasonCode":1001,"custodyTransactionId":"DB:FW_0c4c220c545ed1c0f54c918b2141c79f23ea866f64853c805b27b9f1fd61a6c2"}
```

### Call the Order API

To run the build program:

```
# Set the environments accordingly, following https://github.com/bullish-exchange/api-examples

export BX_API_HOSTNAME=...
export BX_PRIVATE_KEY=...
export BX_JWT=...
export BX_AUTHORIZER=...
```

Run the `create_order` program to place the orders request:

One example output:

```
=== STEP 0. Load Environment Variables =============================================================

% Loaded BX_API_HOSTNAME: https://api.simnext.bullish-test.com
% Loaded BX_PRIVATE_KEY: [--- HIDDEN ---]
% Loaded BX_JWT: [--- HIDDEN ---]
% Loaded BX_AUTHORIZER: C3FE2367E8C90000823E000000000000

=== STEP 1. Get Nonce ==============================================================================

% Sending HTTP request to: https://api.simnext.bullish-test.com/trading-api/v1/nonce
% Received HTTP response status code: 200
% Received HTTP response reason: OK
% Received HTTP response body: {"lowerBound":1671408000000000,"upperBound":1671494399999000}
% Nonce: 1671408000000001

=== STEP 2. Create Order ===========================================================================

% Signature: SIG_R1_JviKVowMYNVE3Z1c4q58a6c96VoqVEqfGLERZGSaajoB36X3Ln4ftFkWncqpKMsdhGPvXcDdtC1mG2qnSSp8Ztceid1TXV
% Sending HTTP request to: https://api.simnext.bullish-test.com/trading-api/v1/orders
% Sending HTTP request with headers:
--- Headers -----
Authorization: [--- HIDDEN ---]
BX-NONCE: 1671408000000001
BX-SIGNATURE: SIG_R1_JviKVowMYNVE3Z1c4q58a6c96VoqVEqfGLERZGSaajoB36X3Ln4ftFkWncqpKMsdhGPvXcDdtC1mG2qnSSp8Ztceid1TXV
BX-TIMESTAMP: 1671416287000
-----------------
% Sending HTTP request with body: {"timestamp":"1671416287000","nonce":"1671408000000001","authorizer":"C3FE2367E8C90000823E000000000000","command":{"commandType":"V1CreateOrder","handle":null,"symbol":"BTCUSD","type":"LMT","side":"BUY","price":"30071.5000","stopPrice":null,"quantity":"1.87000000","timeInForce":"GTC","allowMargin":false}}
% Received HTTP response status code: 200
% Received HTTP response reason: OK
% Received HTTP response body: {"message":"Command acknowledged - CreateOrder","requestId":"524772390270926848","orderId":"524772390270926849","test":false}```
```

### Sign the request digest with the C++ library from a Python driver program

This example program shows calling a binary program built with the C++ library for signing requests from a program written in Python.

```
# follow https://api.exchange.bullish.com/docs/api/rest/#overview--get-your-bullish-account-id to prepare the environment variables
export BX_API_HOSTNAME=...
export BX_PUBLIC_KEY=...
export BX_PRIVATE_KEY=...
export BX_API_METADATA=...
export BX_AUTHORIZER=...
export BX_JWT=...

# call the python tool which calls ./build/example/ecc_signing to sign
./build/example/create_order.py

# expected output like, confirming the order has been placed
{"message":"Command acknowledged - CreateOrder","requestId":"511042106937573376","orderId":"511042106937573377","test":false}
```

## Appendix: Install OpenSSL

Please install latest OpenSSL 3.x from source and install it to `/usr/local`.

As of this writing, OpenSSL version 3.0.8 is the current LTS version and has no vulnerabilities. Please check the OpenSSL [**vulnerabilities page**](https://www.openssl.org/news/vulnerabilities.html) for the latest, safest version and substitute that in below when building.

```
wget https://ftp.openssl.org/source/openssl-3.0.8.tar.gz

tar -xzvf openssl-3.0.8.tar.gz

cd openssl-3.0.8

./config --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic

make

make install
```

## License

EOSIO-Taurus is released under the open source [MIT](./LICENSE) license and is offered "AS IS" without warranty of any kind, express or implied. Any security provided by the EOSIO-Taurus software depends in part on how it is used, configured, and deployed. EOSIO-Taurus is built upon many third-party libraries such as WABT (Apache License) and WAVM (BSD 3-clause) which are also provided "AS IS" without warranty of any kind. You are responsible for reviewing and complying with the license terms included with any third party software that may be provided. Without limiting the generality of the foregoing, Bullish Global and its affiliates make no representation or guarantee that EOSIO-Taurus or any third-party libraries will perform as intended or will be free of errors, bugs or faulty code. Both may fail in large or small ways that could completely or partially limit functionality or compromise computer systems. If you use or implement EOSIO-Taurus, you do so at your own risk. In no event will Bullish Global or its affiliates be liable to any party for any damages whatsoever, even if previously advised of the possibility of damage.

## Important

See [LICENSE](./LICENSE) for copyright and license terms.

All repositories and other materials are provided subject to the terms of this [IMPORTANT](./IMPORTANT.md) notice and you must familiarize yourself with its terms.  The notice contains important information, limitations and restrictions relating to our software, publications, trademarks, third-party resources, and forward-looking statements.  By accessing any of our repositories and other materials, you accept and agree to the terms of the notice.
