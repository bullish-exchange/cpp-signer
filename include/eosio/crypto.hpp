#pragma once

#include <eosio/r1_key.hpp>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string>
#include <array>

namespace eosio {

namespace sha256 {
eosio::checksum256 hash(const std::string &str);
} // ns eosio::sha256

std::string public_key_to_string(const ecc_public_key& key);

ecc_public_key public_key_from_string(const std::string &s);

std::string private_key_to_string(const ecc_private_key& private_key);

ecc_private_key private_key_from_string(const std::string &s);

std::string signature_to_string(const ecc_signature &obj);

ecc_signature signature_from_string(const std::string& s);

template<typename SrcIt, typename DestIt>
bool unhex(DestIt dest, SrcIt begin, SrcIt end) {
  auto get_digit = [&](uint8_t &nibble) {
    if (*begin >= '0' && *begin <= '9')
      nibble = *begin++ - '0';
    else if (*begin >= 'a' && *begin <= 'f')
      nibble = *begin++ - 'a' + 10;
    else if (*begin >= 'A' && *begin <= 'F')
      nibble = *begin++ - 'A' + 10;
    else
      return false;
    return true;
  };
  while (begin != end) {
    uint8_t h, l;
    if (!get_digit(h) || !get_digit(l))
      return false;
    *dest++ = (h << 4) | l;
  }
  return true;
}

} // ns eosio
