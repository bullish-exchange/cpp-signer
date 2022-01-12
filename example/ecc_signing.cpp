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
