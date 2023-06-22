
#include <eosio/crypto.hpp>
#include <eosio/check.hpp>
#include <eosio/abieos_ripemd160.hpp>
#include <eosio/from_bin.hpp>
#include <eosio/to_bin.hpp>
#include <eosio/stream.hpp>

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <string>

#include <cstdint>

namespace eosio {

enum key_type : uint8_t {
  r1_type = 1
};

const char base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::array<int8_t, 256> create_base58_map() {
  std::array<int8_t, 256> base58_map{{0}};
  for (unsigned i = 0; i < base58_map.size(); ++i)
    base58_map[i] = -1;
  for (unsigned i = 0; i < sizeof(base58_chars); ++i)
    base58_map[base58_chars[i]] = i;
  return base58_map;
}

const auto base58_map = create_base58_map();

template<typename Container>
void base58_to_binary(Container &result, const std::string &s) {
  std::size_t offset = result.size();
  for (auto &src_digit: s) {
    int carry = base58_map[static_cast<uint8_t>(src_digit)];
    check(carry >= 0, "Unexpected base58 string");
    for (std::size_t i = offset; i < result.size(); ++i) {
      auto &result_byte = result[i];
      int x = static_cast<uint8_t>(result_byte) * 58 + carry;
      result_byte = x;
      carry = x >> 8;
    }
    if (carry)
      result.push_back(static_cast<uint8_t>(carry));
  }
  for (auto &src_digit: s)
    if (src_digit == '1')
      result.push_back(0);
    else
      break;
  std::reverse(result.begin() + offset, result.end());
}

template<typename Container>
std::string binary_to_base58(const Container &bin) {
  std::string result("");
  for (auto byte: bin) {
    static_assert(sizeof(byte) == 1, "Unexpected bin with element larger than one byte");
    int carry = static_cast<uint8_t>(byte);
    for (auto &result_digit: result) {
      int x = (base58_map[result_digit] << 8) + carry;
      result_digit = base58_chars[x % 58];
      carry = x / 58;
    }
    while (carry) {
      result.push_back(base58_chars[carry % 58]);
      carry = carry / 58;
    }
  }
  for (auto byte: bin)
    if (byte)
      break;
    else
      result.push_back('1');
  std::reverse(result.begin(), result.end());
  return result;
}

template<typename... ContainerS>
void digest_suffix_ripemd160_update(abieos_ripemd160::ripemd160_state* self) { }

template<typename Container, typename... ContainerS>
void digest_suffix_ripemd160_update(abieos_ripemd160::ripemd160_state* self,
                                    const Container& data, const ContainerS& ... more) {
  abieos_ripemd160::ripemd160_update(self, data.data(), data.size());
  digest_suffix_ripemd160_update(self, more...);
}

template<typename... Container>
std::array<unsigned char, 20> digest_suffix_ripemd160(const Container& ... data) {
  std::array<unsigned char, 20> digest;
  abieos_ripemd160::ripemd160_state self;
  abieos_ripemd160::ripemd160_init(&self);

  // C++11 version of the C++17 statement:
  // (abieos_ripemd160::ripemd160_update(&self, data.data(), data.size()), ...);
  digest_suffix_ripemd160_update(&self, data...);

  check(abieos_ripemd160::ripemd160_digest(&self, digest.data()),
        "Failed to calculate ripemd160 digest");
  return digest;
}

namespace sha256 {
checksum256 hash(const std::string& str) {
  checksum256 result;
  SHA256_CTX ctx;

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, reinterpret_cast<const uint8_t *>(str.data()),
                str.size());
  SHA256_Final(reinterpret_cast<uint8_t *>(result.data()), &ctx);

  return result;
}
}

template <typename S>
inline void key_from_bin(ecc_private_key& obj, S& stream) {
  uint32_t key_type_parsed;
  varuint32_from_bin(key_type_parsed, stream);
  eosio::check(key_type_parsed == key_type::r1_type, "Only R1 key is supported for ecc_private_key");
  std::array<char, 32> obj_bytes;
  from_bin(obj_bytes, stream);
  obj = obj_bytes;
}

template <typename S>
void key_to_bin(const ecc_private_key& obj, S& stream) {
  varuint32_to_bin(key_type::r1_type, stream);
  std::array<char, 32> obj_bytes = obj;
  to_bin(obj_bytes, stream);
}

template <typename S>
inline void key_from_bin(ecc_public_key& obj, S& stream) {
  uint32_t key_type_parsed;
  varuint32_from_bin(key_type_parsed, stream);
  eosio::check(key_type_parsed == key_type::r1_type, "Only R1 key is supported");
  std::array<char, 33> obj_bytes;
  from_bin(obj_bytes, stream);
  obj = obj_bytes;
}

template <typename S>
void key_to_bin(const ecc_public_key& obj, S& stream) {
  varuint32_to_bin(key_type::r1_type, stream);
  std::array<char, 33> obj_bytes = obj;
  to_bin(obj_bytes, stream);
}

template <typename S>
inline void key_from_bin(ecc_signature& obj, S& stream) {
  uint32_t key_type_parsed;
  varuint32_from_bin(key_type_parsed, stream);
  eosio::check(key_type_parsed == key_type::r1_type, "Only R1 key is supported");
  std::array<char, 65> obj_bytes;
  from_bin(obj_bytes, stream);
  obj = obj_bytes;
}

template <typename S>
void key_to_bin(const ecc_signature& obj, S& stream) {
  varuint32_to_bin(key_type::r1_type, stream);
  std::array<char, 65> obj_bytes = obj;
  to_bin(obj_bytes, stream);
}

template<typename Key>
Key string_to_key(const std::string &s, key_type type, const std::string &suffix) {
  std::vector<char> whole;
  whole.push_back(uint8_t{type});
  base58_to_binary(whole, s);
  check(whole.size() > 5,
        "Unexpected key string");
  auto ripe_digest = digest_suffix_ripemd160(std::string(whole.data() + 1, whole.size() - 5), suffix);
  check(memcmp(ripe_digest.data(), whole.data() + whole.size() - 4, 4) == 0,
        "Key string ripemd160 checksum is invalid");
  whole.erase(whole.end() - 4, whole.end());

  //  return convert_from_bin<Key>(whole);
  Key key;
  input_stream stream{whole};
  key_from_bin(key, stream);
  return key;
}

template<typename Key>
std::string key_to_string(const Key &key, const std::string &suffix, const char *prefix) {
//  auto whole = convert_to_bin<Key>(key);
  std::vector<char> whole;
  size_stream ss;
  key_to_bin(key, ss);
  whole.resize(ss.size);
  fixed_buf_stream fbs(whole.data(), ss.size);
  key_to_bin(key, fbs);
  check( fbs.pos == fbs.end, convert_stream_error(stream_error::underrun) );

  auto ripe_digest = digest_suffix_ripemd160(std::string(whole.data() + 1, whole.size() - 1), suffix);
  whole.insert(whole.end(), ripe_digest.data(), ripe_digest.data() + 4);
  return prefix + binary_to_base58(std::string(whole.data() + 1, whole.size() - 1));
}


std::string public_key_to_string(const ecc_public_key& key) {
  return key_to_string(key, "R1", "PUB_R1_");
}

eosio::ecc_public_key public_key_from_string(const std::string &s) {
  eosio::ecc_public_key result;
  if (s.substr(0, 7) == "PUB_R1_") {
    return string_to_key<eosio::ecc_public_key>(s.substr(7), key_type::r1_type, "R1");
  } else {
    eosio::check(false, "Unexpected public key format - only PUB_R1_* is supported");
    __builtin_unreachable();
  }
}

std::string private_key_to_string(const ecc_private_key& private_key) {
    return key_to_string(private_key, "R1", "PVT_R1_");
}

eosio::ecc_private_key private_key_from_string(const std::string &s) {
  if (s.substr(0, 7) == "PVT_R1_") {
    return string_to_key<ecc_private_key>(s.substr(7), key_type::r1_type, "R1");
  } else {
    check(false, "Unexpected private key format - only PVT_R!_* is supported");
    __builtin_unreachable();
  }
}

std::string signature_to_string(const eosio::ecc_signature &signature) {
  return key_to_string(signature, "R1", "SIG_R1_");
}

ecc_signature signature_from_string(const std::string& s) {
  if (s.size() >= 7 && s.substr(0, 7) == "SIG_R1_") {
    return string_to_key<ecc_signature>(s.substr(7), key_type::r1_type, "R1");
  } else {
    check(false, "Unexpected signature format - only SIG_R1_* is supported");
    __builtin_unreachable();
  }
}

} // namespace eosio
