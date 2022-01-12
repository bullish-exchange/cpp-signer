#include <eosio/fixed_bytes.hpp>
#include <openssl/sha.h>

namespace eosio {
namespace sha256 {
eosio::checksum256 hash(std::string_view str) {
  eosio::checksum256 result;
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, reinterpret_cast<const uint8_t *>(str.data()),
                str.size());
  SHA256_Final(reinterpret_cast<uint8_t *>(result.data()), &ctx);

  return result;
}
} // namespace sha256
} // namespace eosio
