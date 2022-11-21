#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <string_view>
#include <string>
#include <array>

namespace eosio {

using ecc_public_key = std::array<char, 33>;
using ecc_private_key = std::array<char, 32>;
using ecc_signature = std::array<char, 65>;

template <std::size_t Size, typename Word> class fixed_bytes;
using checksum256 = fixed_bytes<32, std::uint64_t>;

namespace r1 {

EC_KEY *new_r1_key();

class public_key {
public:
  public_key() : key(new_r1_key()) {}
  ~public_key() {
    if (key)
      EC_KEY_free(key);
  }

  public_key(const public_key &) = delete;
  public_key(public_key &&other) : key(other.key) { other.key = nullptr; }
  public_key(const ecc_public_key &data);
  public_key(const ecc_signature &c, const eosio::checksum256 &digest);
  public_key &operator=(const public_key &) = delete;
  public_key &operator=(public_key &&other) {
    key = other.key;
    other.key = nullptr;
    return *this;
  }

  public_key(std::string_view str);
  public_key(EC_KEY *k) : key(k) {}

  ecc_public_key serialize() const;

  EC_KEY *get() const { return key; }

private:
  friend class private_key;
  EC_KEY *key;
};

class private_key {
public:
  private_key() : key(new_r1_key()) {}
  ~private_key() {
    if (key)
      EC_KEY_free(key);
  }

  private_key(const private_key &) = delete;
  private_key(private_key &&other) : key(other.key) { other.key = nullptr; }
  private_key(const ecc_private_key &data);
  private_key(std::string_view str);
  private_key &operator=(const private_key &) = delete;
  private_key &operator=(private_key &&other) {
    key = other.key;
    other.key = nullptr;
    return *this;
  }

  public_key get_public_key() const;

  ecc_signature sign_compact(const eosio::checksum256 &digest) const;
  std::string sign(std::string_view input) const;
  std::string sign_digest(std::string_view digest) const;

  static private_key generate();
  ecc_private_key serialize() const;

private:
  EC_KEY *key;
};

} // namespace r1
} // namespace eosio