#pragma once

// Note: this header is the exported interface for the cpp-signer library
//       only common or standard libraries should be included here, to simplify the dependency and
//       accelerate the building of the application using this library

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <array>

namespace eosio {

using ecc_public_key = std::array<char, 33>;
using ecc_private_key = std::array<char, 32>;
using ecc_signature = std::array<char, 65>;

using checksum256 = std::array<char, 32>;

namespace r1 {

EC_KEY *new_r1_key();

class public_key {
public:
  public_key() : key(new_r1_key()) {}
  ~public_key() {
    if (key) {
      EC_KEY_free(key);
    }
  }

  public_key(const public_key& other);
  public_key(public_key&& other) : key(other.key) { other.key = nullptr; }
  public_key(const ecc_public_key& data);
  public_key(const ecc_signature& c, const eosio::checksum256& digest);

  public_key(const std::string& str);
  public_key(EC_KEY *k) : key(k) {}

  ecc_public_key serialize() const;

  EC_KEY *get() const { return key; }

  bool verify(const std::string& message, const std::string& sigature) const;

private:
  friend class private_key;
  EC_KEY* key = nullptr;

private:
  void set(const ecc_public_key& data);
};

class private_key {
public:
  private_key() : key(new_r1_key()) {}
  ~private_key() {
    if (key)
      EC_KEY_free(key);
  }

  private_key(const private_key& other);
  private_key(private_key&& other) : key(other.key) { other.key = nullptr; }
  private_key(const ecc_private_key& data);
  private_key(const std::string& str);

  public_key get_public_key() const;

  ecc_signature sign_compact(const eosio::checksum256& digest) const;
  std::string sign(const std::string& input) const;
  std::string sign_digest(const std::string& digest) const;

  static private_key generate();
  ecc_private_key serialize() const;

private:
  EC_KEY* key = nullptr;

private:
  void set(const ecc_private_key& data);
};

/*
 * This function accepts standard ECDSA R1 keys and sigantures and verifies it.
 *
 * Curve - ECDSA R1 (prime256v1 or secp256r1 or P-256 in different docs)
 * Public key format - X.509 SubjectPublicKeyInfo format, PEM encoded
 * Hashing algorithm used during signing - sha256
 * Encoding of the signature - DER
*/
bool verify_ecdsa_sig(const std::string& message, const std::string& signature,
                      const std::string& public_key);

} // namespace r1
} // namespace eosio
