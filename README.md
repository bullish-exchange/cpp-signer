# eosio-signing-example

This repo provides the library and minimal C++ code example to sign any arbitrary message with an EOSIO R1 key and produce an EOSIO signature (k1 keys are not yet supported).

to compile:
```
cmake -DCMAKE_BUILD_TYPE=Release -S. -Bbuild && cmake --build build
```


## How to - integration into your own project

In your CMakeLists.txt 

```
include(FetchContent)
cmake_minimum_required (VERSION 3.10)
project(
  use_eosio_r1_key
  VERSION 1.0
  LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)

### TODO: change to following GIT_TAG value to the appropriate commit hash
FetchContent_Declare(
  eosio_r1_key
  GIT_REPOSITORY https://github.com/b1-as/eosio-signing-example
  GIT_TAG e579075b714a1a3bd40436dcb29c575ddd83859b
)
FetchContent_MakeAvailable(eosio_r1_key)

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

## For CentOS 7 

Requires C++17 support. We have tested with g++ 10.2.1 
```
# g++ --version
g++ (GCC) 10.2.1 20210130 (Red Hat 10.2.1-11)
```

Our Centos 7 version information
```
# cat /etc/centos-release
CentOS Linux release 7.9.2009 (Core)
```


### Install openssl
The system default OpenSSL package won't work. Please install latest OpenSSL 1.1 from source and install it to `/usr/local`. 

As of this writing, OpenSSL version 1.1.1n is current and has no vulnerabilities. Please check the OpenSSL [**vulnerabilities page**](https://www.openssl.org/news/vulnerabilities.html) for the latest, safest 1.1 version and substitute that in below when building.

```
wget https://ftp.openssl.org/source/openssl-1.1.1n.tar.gz

tar -xzvf openssl-1.1.1n.tar.gz

cd openssl-1.1.1n

./config --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic

make

make install
```


### Build static library
static library generation and running tests
```
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON -DCMAKE_BUILD_TYPE=Release -S. -Bbuild -DOPENSSL_ROOT_DIR=/usr/local && cmake --build build

cd build

ctest

```

### Build dynamic library
shared library generation and running tests
```
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

cmake -DEOSIO_R1_KEY_ENABLE_TEST=ON -DEOSIO_R1_KEY_ENABLE_EXAMPLE=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -S. -Bbuild -DOPENSSL_ROOT_DIR=/usr/local && cmake --build build

cd build

ctest
```


### Run the example app

```
cd build/example

ecc_signing
```

## License

EOSIO is released under the open source [MIT](./LICENSE) license and is offered “AS IS” without warranty of any kind, express or implied. Any security provided by the EOSIO software depends in part on how it is used, configured, and deployed. EOSIO is built upon many third-party libraries such as WABT (Apache License) and WAVM (BSD 3-clause) which are also provided “AS IS” without warranty of any kind. Without limiting the generality of the foregoing, Block.one makes no representation or guarantee that EOSIO or any third-party libraries will perform as intended or will be free of errors, bugs or faulty code. Both may fail in large or small ways that could completely or partially limit functionality or compromise computer systems. If you use or implement EOSIO, you do so at your own risk. In no event will Block.one be liable to any party for any damages whatsoever, even if it had been advised of the possibility of damage.  

## Important

See [LICENSE](./LICENSE) for copyright and license terms.

All repositories and other materials are provided subject to the terms of this [IMPORTANT](./IMPORTANT.md) notice and you must familiarize yourself with its terms.  The notice contains important information, limitations and restrictions relating to our software, publications, trademarks, third-party resources, and forward-looking statements.  By accessing any of our repositories and other materials, you accept and agree to the terms of the notice.
