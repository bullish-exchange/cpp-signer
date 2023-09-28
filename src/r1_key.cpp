#include <eosio/check.hpp>
#include <eosio/crypto.hpp>
#include <eosio/r1_key.hpp>

#include "base64.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#define ASSERT(cond, msg)                                                     \
  if (!(cond)) {                                                              \
    throw std::runtime_error(format_error_message(msg, __FILE__, __LINE__));  \
  }

static std::string format_error_message(const std::string& msg,
                                        const std::string &file,
                                        int line) {
  return msg + " " + file + ":" + std::to_string(line);
}

static void elog(const std::string &str) {
#ifndef NDEBUG
  std::cerr << str << std::endl;
#endif
}

static void elog_openssl_err(const std::string& msg) {
#ifndef NDEBUG
   if (const char* openssl_err = ERR_error_string(ERR_get_error(), NULL)) {
      elog(msg + std::string(": ") + openssl_err);
   } else {
      elog(msg);
   }
#endif
}

static EC_KEY* get_pubkey_from_pem(const char* pem, size_t pem_len) {
   EC_KEY* ec_key = NULL;
   BIO* bio = BIO_new_mem_buf(pem, pem_len);
   if (bio) {
      ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
   }
   BIO_free(bio);
   return ec_key;
}

namespace eosio {
namespace r1 {

EC_KEY *new_r1_key() {
  EC_KEY *r = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  ASSERT(r, "Unable to create R1 key");
  return r;
}

template <typename T, typename Deleter>
std::unique_ptr<T, Deleter> make_unique_ptr(T *ptr, Deleter deleter) {
  ASSERT(ptr, __PRETTY_FUNCTION__);
  return std::unique_ptr<T, Deleter>(ptr, deleter);
}

auto make_ssl_bignum() -> decltype(make_unique_ptr(BN_new(), BN_free)) {
  return make_unique_ptr(BN_new(), BN_free);
}

auto dup_ssl_bignum(const BIGNUM *from)
  -> decltype(make_unique_ptr(BN_dup(from), BN_free)) {
  return make_unique_ptr(BN_dup(from), BN_free);
}

int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig,
                              const unsigned char *msg, int msglen, int recid,
                              int check) {
  int ret = 0;
  BN_CTX *ctx = NULL;

  BIGNUM *x = NULL;
  BIGNUM *e = NULL;
  BIGNUM *order = NULL;
  BIGNUM *sor = NULL;
  BIGNUM *eor = NULL;
  BIGNUM *field = NULL;
  EC_POINT *R = NULL;
  EC_POINT *O = NULL;
  EC_POINT *Q = NULL;
  BIGNUM *rr = NULL;
  BIGNUM *zero = NULL;
  int n = 0;
  int i = recid / 2;

  const BIGNUM *r, *s;
  ECDSA_SIG_get0(ecsig, &r, &s);

  const EC_GROUP *group = EC_KEY_get0_group(eckey);
  if ((ctx = BN_CTX_new()) == NULL) {
    ret = -1;
    goto err;
  }
  BN_CTX_start(ctx);
  order = BN_CTX_get(ctx);
  if (!EC_GROUP_get_order(group, order, ctx)) {
    ret = -2;
    goto err;
  }
  x = BN_CTX_get(ctx);
  if (!BN_copy(x, order)) {
    ret = -1;
    goto err;
  }
  if (!BN_mul_word(x, i)) {
    ret = -1;
    goto err;
  }
  if (!BN_add(x, x, r)) {
    ret = -1;
    goto err;
  }
  field = BN_CTX_get(ctx);
  if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) {
    ret = -2;
    goto err;
  }
  if (BN_cmp(x, field) >= 0) {
    ret = 0;
    goto err;
  }
  if ((R = EC_POINT_new(group)) == NULL) {
    ret = -2;
    goto err;
  }
  if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) {
    ret = 0;
    goto err;
  }
  if (check) {
    if ((O = EC_POINT_new(group)) == NULL) {
      ret = -2;
      goto err;
    }
    if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) {
      ret = -2;
      goto err;
    }
    if (!EC_POINT_is_at_infinity(group, O)) {
      ret = 0;
      goto err;
    }
  }
  if ((Q = EC_POINT_new(group)) == NULL) {
    ret = -2;
    goto err;
  }
  n = EC_GROUP_get_degree(group);
  e = BN_CTX_get(ctx);
  if (!BN_bin2bn(msg, msglen, e)) {
    ret = -1;
    goto err;
  }
  if (8 * msglen > n)
    BN_rshift(e, e, 8 - (n & 7));
  zero = BN_CTX_get(ctx);
  BN_zero(zero);
  if (!BN_mod_sub(e, zero, e, order, ctx)) {
    ret = -1;
    goto err;
  }
  rr = BN_CTX_get(ctx);
  if (!BN_mod_inverse(rr, r, order, ctx)) {
    ret = -1;
    goto err;
  }
  sor = BN_CTX_get(ctx);
  if (!BN_mod_mul(sor, s, rr, order, ctx)) {
    ret = -1;
    goto err;
  }
  eor = BN_CTX_get(ctx);
  if (!BN_mod_mul(eor, e, rr, order, ctx)) {
    ret = -1;
    goto err;
  }
  if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) {
    ret = -2;
    goto err;
  }
  if (!EC_KEY_set_public_key(eckey, Q)) {
    ret = -2;
    goto err;
  }

  ret = 1;

err:
  if (ctx) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (R != NULL)
    EC_POINT_free(R);
  if (O != NULL)
    EC_POINT_free(O);
  if (Q != NULL)
    EC_POINT_free(Q);
  return ret;
}

eosio::ecc_signature signature_from_ecdsa(const EC_KEY *key,
                                          const ecc_public_key& pub_data,
                                          ECDSA_SIG *sig,
                                          const eosio::checksum256& d,
                                          int nBitsR, int nBitsS) {

  const BIGNUM *sig_r, *sig_s;
  ECDSA_SIG_get0(sig, &sig_r, &sig_s);
  auto r = dup_ssl_bignum(sig_r);
  auto s = dup_ssl_bignum(sig_s);

  // want to always use the low S value
  const EC_GROUP *group = EC_KEY_get0_group(key);
  auto order = make_ssl_bignum();
  auto halforder = make_ssl_bignum();
  EC_GROUP_get_order(group, order.get(), nullptr);
  BN_rshift1(halforder.get(), order.get());
  if (BN_cmp(s.get(), halforder.get()) > 0)
    BN_sub(s.get(), order.get(), s.get());

  eosio::ecc_signature csig{'\0'};

  // transfer the ownership of r and s to sig
  auto rr = r.release();
  auto ss = s.release();
  ECDSA_SIG_set0(sig, rr, ss);

  int nRecId = -1;
  for (int i = 0; i < 4; i++) {
    public_key keyRec;
    if (ECDSA_SIG_recover_key_GFp(keyRec.get(), sig, (unsigned char *)&d,
                                  sizeof(d), i, 1) == 1) {
      if (keyRec.serialize() == pub_data) {
        nRecId = i;
        break;
      }
    }
  }
  ASSERT(nRecId != -1, "unable to construct recoverable key");

  csig[0] = nRecId + 27 + 4;
  BN_bn2bin(rr, (unsigned char *)&csig[33 - (nBitsR + 7) / 8]);
  BN_bn2bin(ss, (unsigned char *)&csig[65 - (nBitsS + 7) / 8]);
  return csig;
}

void public_key::set(const ecc_public_key& data) {
  const char *front = &data[0];
  if (*front == 0) {
    ASSERT(key, "invalid public key - the first char is not '\0'");
  } else {
    key = o2i_ECPublicKey(&key, (const unsigned char **)&front, data.size());
    ASSERT(key, "invalid public key");
  }
}

public_key::public_key(const std::string& str)
    : key(new_r1_key()) {
  set(eosio::public_key_from_string(str));
}

public_key::public_key(const ecc_public_key& data) : key(new_r1_key()) {
  set(data);
}

public_key::public_key(const public_key& other) : key(new_r1_key()) {
  EC_KEY_copy(key, other.key);
}

public_key::public_key(const eosio::ecc_signature& c,
                       const eosio::checksum256& digest)
    :  key(new_r1_key()) {
  int nV = c[0];
  ASSERT(nV >= 27 && nV < 35, "invalid r1 signature");

  auto sig = make_unique_ptr(ECDSA_SIG_new(), ECDSA_SIG_free);
  auto r = make_ssl_bignum();
  auto s = make_ssl_bignum();
  BN_bin2bn((const unsigned char *)&c[1], 32, r.get());
  BN_bin2bn((const unsigned char *)&c[33], 32, s.get());

  const EC_GROUP *group = EC_KEY_get0_group(key);
  auto order = make_ssl_bignum();
  auto halforder = make_ssl_bignum();
  EC_GROUP_get_order(group, order.get(), nullptr);
  BN_rshift1(halforder.get(), order.get());
  ASSERT(BN_cmp(s.get(), halforder.get()) <= 0,
         "invalid high s-value encountered in r1 signature");

  ECDSA_SIG_set0(sig.get(), r.release(), s.release());

  if (nV >= 31) {
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
    nV -= 4;
  }

  ASSERT(ECDSA_SIG_recover_key_GFp(key, sig.get(), (unsigned char *)&digest,
                                   sizeof(digest), nV - 27, 0) == 1 ,
         "unable to reconstruct public key from signature");
}

ecc_public_key public_key::serialize() const {
  ecc_public_key dat;
  ASSERT(key, "empty public key");
  EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
  char *front = dat.data();
  i2o_ECPublicKey(key, (unsigned char **)&front);
  return dat;
}

void private_key::set(const ecc_private_key& data) {
  auto d = BN_bin2bn(reinterpret_cast<const uint8_t *>(data.data()),
                     data.size(), NULL);

  ASSERT(EC_KEY_set_private_key(key, d), "invalid private key");
}

private_key::private_key(const private_key& other) : key(new_r1_key()) {
  EC_KEY_copy(key, other.key);
}

private_key::private_key(const ecc_private_key& data) : key(new_r1_key()) {
  set(data);
}

private_key::private_key(const std::string& str) : key(new_r1_key()) {
  set(eosio::private_key_from_string(str));
}

public_key private_key::get_public_key() const {
  public_key pub;
  const EC_GROUP *group = EC_KEY_get0_group(key);
  auto pub_key_point = make_unique_ptr(EC_POINT_new(group), EC_POINT_free);
  auto ctx = make_unique_ptr(BN_CTX_new(), BN_CTX_free);
  const char *error_msg = "unable to convert private key to public key";
  ASSERT(EC_POINT_mul(group, pub_key_point.get(), EC_KEY_get0_private_key(key),
                      NULL, NULL, ctx.get()),
         error_msg);
  ASSERT(EC_KEY_set_public_key(pub.key, pub_key_point.get()), error_msg);
  return pub;
}

eosio::ecc_signature
private_key::sign_compact(const eosio::checksum256& digest) const {
  auto my_pub_key = get_public_key().serialize(); // just for good measure

  while (true) {
    auto sig = make_unique_ptr(
        ECDSA_do_sign((unsigned char *)&digest, sizeof(digest), key),
        ECDSA_SIG_free);

    const BIGNUM *sig_r, *sig_s;
    ECDSA_SIG_get0(sig.get(), &sig_r, &sig_s);
    int nBitsR = BN_num_bits(sig_r);
    int nBitsS = BN_num_bits(sig_s);
    if (nBitsR < 256 && nBitsS < 256)
      return signature_from_ecdsa(key, my_pub_key, sig.get(), digest, nBitsR,
                                  nBitsS);
  }
}

std::string private_key::sign(const std::string& input) const {
  return eosio::signature_to_string(sign_compact(eosio::sha256::hash(input)));
}

std::string private_key::sign_digest(const std::string& digest) const {
  ASSERT(digest.size() == 64, "Digest length is not 64");

  eosio::checksum256 checksum;
  if (!eosio::unhex(reinterpret_cast<uint8_t *>(checksum.data()),
                                                digest.begin(),
                                                digest.end())) {
    ASSERT(false, "Digest is not a hex string");
    __builtin_unreachable();
  };

  return eosio::signature_to_string(sign_compact(checksum));
}

private_key private_key::generate() {
  private_key self;
  ASSERT(EC_KEY_generate_key(self.key), "ecc key generation error");
  return self;
}

ecc_private_key private_key::serialize() const {
  ecc_private_key result;
  auto bn = EC_KEY_get0_private_key(key);
  BN_bn2bin(bn, (unsigned char *)result.data()) ;
  return result;
}

// Note that this refers to the standard (common) ECDSA signature
// encoding/decoding form, and has nothing to do with the one with that usual
// eosio code uses.
bool verify_ecdsa_sig(const std::string& message, const std::string& signature,
                      const std::string& public_key) {
  const std::string prefix =
    "verify_ecdsa_sig(message, signature, public_key) ";
  if (message.empty()) {
    elog(prefix + "message can't be empty");
    return false;
  }
  if (signature.empty()) {
    elog(prefix + "signature can't be empty");
    return false;
  }
  EC_KEY *ec_key = NULL;
  ECDSA_SIG *sig = NULL;
  try {
    if (!(ec_key =
        get_pubkey_from_pem(public_key.c_str(), public_key.size()))) {
      elog_openssl_err(prefix + "EC_KEY inside public_key is a null pointer");
      return false;
    }
    const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);
    if (!ec_group) {
      elog_openssl_err(prefix + "Error getting EC_GROUP");
      EC_KEY_free(ec_key);
      return false;
    }
    if (EC_GROUP_get_curve_name(ec_group) != NID_X9_62_prime256v1) {
      elog_openssl_err(prefix + "Error validating secp256r1 curve");
      EC_KEY_free(ec_key);
      return false;
    }
    unsigned char digest[SHA256_DIGEST_LENGTH];
    auto *res = SHA256(reinterpret_cast<const unsigned char *>(message.data()),
                       message.size(), digest);
    if (!res) {
      elog_openssl_err(prefix + "Error getting SHA-256 hash");
      EC_KEY_free(ec_key);
      return false;
    }
    const std::string sig_decoded = base64_decode(signature);
    auto *sig_data =
        reinterpret_cast<const unsigned char *>(sig_decoded.data());
    sig = d2i_ECDSA_SIG(NULL, &sig_data, sig_decoded.size());
    if (!sig) {
      elog_openssl_err(prefix + "Error decoding signature");
      EC_KEY_free(ec_key);
      return false;
    }
    bool result = (ECDSA_do_verify(digest, sizeof(digest), sig, ec_key) == 1);
    if (!result) {
      elog_openssl_err(prefix + "Error verifying signature");
    }

    EC_KEY_free(ec_key);
    ECDSA_SIG_free(sig);
    return result;
  } catch (const std::exception &e) {
    elog(prefix + "exception: " + e.what());
  } catch (...) {
    elog(prefix + "unknown exception");
  }
  EC_KEY_free(ec_key);
  ECDSA_SIG_free(sig);
  return false;
}

} // namespace r1
} // namespace eosio
