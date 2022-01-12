#include <eosio/crypto.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/r1_key.hpp>
#include <iostream>

namespace eosio {
namespace sha256 {
eosio::checksum256 hash(std::string_view str);
}
} // namespace eosio

bool verify_signing(const eosio::r1::private_key &priv_key, const char *txt,
                    int i) {
  auto pub_key = priv_key.get_public_key();
  auto signature_txt = priv_key.sign(txt);
  auto signature = eosio::signature_from_string(signature_txt);
  auto ecc_sig = std::get<1>(signature);
  auto pub_key_from_signature =
      eosio::r1::public_key(ecc_sig, eosio::sha256::hash(txt));

  if (pub_key.serialize() != pub_key_from_signature.serialize()) {
    std::cerr << "public key from signature does not match the one from "
                 "private key, iteration "
              << i << "\n"
              << "  private_key              : "
              << eosio::private_key_to_string(eosio::private_key{
                     std::in_place_index<1>, priv_key.serialize()})
              << "\n"
              << "  public_key               : "
              << eosio::public_key_to_string(eosio::public_key{
                     std::in_place_index<1>, pub_key.serialize()})
              << "\n"
              << "  public_key from signature: "
              << eosio::public_key_to_string(
                     eosio::public_key{std::in_place_index<1>,
                                       pub_key_from_signature.serialize()})
              << "\n"
              << "  signature                : " << signature_txt << "\n";
    return false;
  }
  return true;
}

int main() {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
  const char *test_json =
      R"x({"accountId":"abc","nonce":1,"expirationTime":1636755051,"biometricsUsed":false,"sessionKey":null})x";

  for (int i = 0; i < 100; ++i) {
    eosio::r1::private_key priv_key(
        "PVT_R1_23o8wEtWV2AayohHfm5C8K84jyZiKKbo3de6fGffQNVBWjEEJ4");
    if (!verify_signing(priv_key, test_json, i))
      return 1;
  }
  return 0;
}
