#include <eosio/r1_key.hpp>
#include <eosio/crypto.hpp>

#include <iostream>

bool verify_signing(const eosio::r1::private_key& priv_key, const char *txt, int i) {
  auto pub_key = priv_key.get_public_key(); // derived public key from the private key
  auto signature_txt = priv_key.sign(txt); // sign the payload message
  auto signature = eosio::signature_from_string(signature_txt);
  auto pub_key_from_signature =
      eosio::r1::public_key(signature, eosio::sha256::hash(txt)); // recover public key from the signature

  if (pub_key.serialize() != pub_key_from_signature.serialize()) {
    std::cerr << "public key from signature does not match the one from "
                 "private key, iteration "
              << i << "\n"
              << "  private_key              : "
              << eosio::private_key_to_string(priv_key.serialize())
              << "\n"
              << "  public_key               : "
              << eosio::public_key_to_string(pub_key.serialize())
              << "\n"
              << "  public_key from signature: "
              << eosio::public_key_to_string(pub_key_from_signature.serialize())
              << "\n"
              << "  signature                : "
              << signature_txt << "\n";
    return false;
  }
  return true;
}


bool verify_signing_digest(const eosio::r1::private_key& priv_key, const char *txt, const char *digest, int i) {
  auto pub_key = priv_key.get_public_key(); // derived public key from the private key
  auto signature_txt = priv_key.sign_digest(digest); // sign the payload message's digest
  auto signature = eosio::signature_from_string(signature_txt);
  auto pub_key_from_signature =
      eosio::r1::public_key(signature, eosio::sha256::hash(txt)); // recover public key from the signature

  if (pub_key.serialize() != pub_key_from_signature.serialize()) {
    std::cerr << "public key from signature from digest does not match the one from "
                 "private key, iteration "
              << i << "\n"
              << "  private_key              : "
              << eosio::private_key_to_string(priv_key.serialize())
              << "\n"
              << "  public_key               : "
              << eosio::public_key_to_string(pub_key.serialize())
              << "\n"
              << "  public_key from signature: "
              << eosio::public_key_to_string(pub_key_from_signature.serialize())
              << "\n"
              << "  signature                : "
              << signature_txt << "\n";
    return false;
  }
  return true;
}

template<typename CharT>
static std::string to_hex(const CharT* d, uint32_t s) {
  std::string r;
  const char* to_hex="0123456789abcdef";
  uint8_t* c = (uint8_t*)d;
  for( uint32_t i = 0; i < s; ++i ) {
    (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
  }
  return r;
}

std::string checksum_to_str(const eosio::checksum256& checksum) {
  return to_hex(checksum.data(), checksum.size());
}

int main() {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

  // test payload test_json
  const char *test_json =
      R"x({"accountId":"abc","nonce":1,"expirationTime":1636755051,"biometricsUsed":false,"sessionKey":null})x";

  // sha256 digest hex string of the test payload
  const char *test_json_sha = "3a553834f0aae08f8b3f7e85777f9334f772971777d3d06e2b3aced27b0c203d";

  const std::string priv_key_str = "PVT_R1_23o8wEtWV2AayohHfm5C8K84jyZiKKbo3de6fGffQNVBWjEEJ4";
  eosio::r1::private_key priv_key(priv_key_str);

  auto priv_key_str_converted = eosio::private_key_to_string(priv_key.serialize());
  if (priv_key_str_converted != priv_key_str) {
    std::cerr << "private key converted back is not the same as the original string\n";
    return 1;
  }

  // sign payload
  for (int i = 0; i < 100; ++i) {
    if (!verify_signing(priv_key, test_json, i)) {
      return 1;
    }
  }

  // sign the sha256 digest hex string of the payload
  for (int i = 0; i < 100; ++i) {
    if (!verify_signing_digest(priv_key, test_json, test_json_sha, i)) {
      return 1;
    }
  }

  return 0;
}
