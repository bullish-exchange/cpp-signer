#include <eosio/r1_key.hpp>
#include <iostream>

// Usage: ./ecc_signing [key] [payload or payload's sha256 digest]

int main(int argc, char *argv[]) {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

  std::string test_json{R"x({"accountId":"abc","nonce":1,"expirationTime":1636755051,"biometricsUsed":false,"sessionKey":null})x"};
  // The private key in this example is coded into the source. In production settings please store the private key in an environment variable and retrieve it here
  std::string test_key{"PVT_R1_iyQmnyPEGvFd8uffnk152WC2WryBjgTrg22fXQryuGL9mU6qW"};

  std::string key = test_key;
  std::string payload = test_json;

  if (argc >= 3) {
    key = argv[1];
    payload = argv[2];
  }

  eosio::r1::private_key priv_key{key};

  if (payload[0] == '{') {
    // input is the payload message
    std::cerr << "Signing with payload: " << payload << std::endl;
    std::cout << priv_key.sign(payload) << "\n";
  } else {
    // input is the hex string of the payload message's sha256 checksum
    std::cerr << "Signing with digest: " << payload << std::endl;
    std::cout << priv_key.sign_digest(payload) << "\n";
  }

  return 0;
}
