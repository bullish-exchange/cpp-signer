#include <eosio/r1_key.hpp>

#include "base64.h"

#include <iostream>
#include <string>

const std::string MESSAGE_1 = "message to sign";
const std::string SIGNATURE_1 =
      "MEYCIQCi5byy/JAvLvFWjMP8ls7z0ttP8E9UApmw69OBzFWJ3gIhANFE2l3jO3L8c/kwEfu"
      "WMnh8q1BcrjYx3m368Xc/7QJU";
const std::string SIGNATURE_1_BAD =
      "MEYCIQCi5byy/JAvLvFWjMP8ls7z0ttP8E9UApmw69OBzFWJ3gIhANFE2l3jO3L8c/kwEfu"
      "WMnh8q1BcrjYx3m368Xc/7QJV"; // changed the ending U to V
const std::string PUBLIC_KEY_1 =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzjca5ANoUF+XT+4gIZj2/X3V2UuT\n"
      "E9MTw3sQVcJzjyC/p7KeaXommTC/7n501p4Gd1TiTiH+YM6fw/YYJUPSPg==\n"
      "-----END PUBLIC KEY-----";

const std::string MESSAGE_2 =
    "29762818433811676281843385POST/v1/"
    "withdraw{\"accountType\":\"EXCHANGE\",\"toAddress\":"
    "\"b5a40facbce2076d35c43575884a05031ad4892ef96ca241a603e3c006b6617f\","
    "\"tag\":"
    "\"093434a3ee9e0a010bb2c2aae06c2614dd24894062a1caf26718a01e175569b8\","
    "\"coinSymbol\":\"EOS\",\"network\":\"EOS.IO\",\"amount\":\"1\","
    "\"isGross\":false,\"maxFee\":\"0.1\"}";
const std::string SIGNATURE_2 =
      "MEYCIQCW+qT0iavP4v+YfF+QOWvsGpt6huqENzuyL6BhqLOI4QIhAN9Xcxi7ocSED9AGLTb"
      "LGlyiXCA8Lb+L+trl7J5tMdqo";
const std::string PUBLIC_KEY_2 =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVfldzw4nQlTxeOVsRZucmVwxpvZ\n"
      "IjWfHg7wRlnITCmIneW3oGm2j5ezpRQQ7bMMQay83MMgw5w+mqCZwuFPyA==\n"
      "-----END PUBLIC KEY-----";
const std::string PUBLIC_KEY_2_DIFFERENT_NEWLINES =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVfldzw4nQlTxeOVs\n"
      "RZucmVwxpvZ\n"
      "IjWfHg7wRlnITCmIneW3oGm2j5ezpRQQ7bMMQay83MMg\n"
      "w5w+mqCZwuFPyA==\n"
      "-----END PUBLIC KEY-----";
const std::string PUBLIC_KEY_2_NO_NEWLINES_IN_BODY =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVfldzw4nQlTxeOVsRZucmVwxpvZ"
      "IjWfHg7wRlnITCmIneW3oGm2j5ezpRQQ7bMMQay83MMgw5w+mqCZwuFPyA==\n"
      "-----END PUBLIC KEY-----";
const std::string PUBLIC_KEY_2_EXTRA_ENDING_NEWLINE =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVfldzw4nQlTxeOVsRZucmVwxpvZ"
      "IjWfHg7wRlnITCmIneW3oGm2j5ezpRQQ7bMMQay83MMgw5w+mqCZwuFPyA==\n"
      "-----END PUBLIC KEY-----\n";
const std::string PUBLIC_KEY_2_NO_NEWLINES_AT_ALL =
      "-----BEGIN PUBLIC KEY-----"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYVfldzw4nQlTxeOVsRZucmVwxpvZ"
      "IjWfHg7wRlnITCmIneW3oGm2j5ezpRQQ7bMMQay83MMgw5w+mqCZwuFPyA=="
      "-----END PUBLIC KEY-----";
const std::string LINE = std::string(18, '=');

bool verify_case_1() {
  return eosio::r1::verify_ecdsa_sig(MESSAGE_1, SIGNATURE_1, PUBLIC_KEY_1) &&
     not eosio::r1::verify_ecdsa_sig(MESSAGE_1, SIGNATURE_1_BAD, PUBLIC_KEY_1);
}

bool verify_case_2() {
  return eosio::r1::verify_ecdsa_sig(MESSAGE_2, SIGNATURE_2, PUBLIC_KEY_2) &&
         eosio::r1::verify_ecdsa_sig(MESSAGE_2, SIGNATURE_2, PUBLIC_KEY_2_DIFFERENT_NEWLINES) &&
         eosio::r1::verify_ecdsa_sig(MESSAGE_2, SIGNATURE_2, PUBLIC_KEY_2_NO_NEWLINES_IN_BODY) &&
         eosio::r1::verify_ecdsa_sig(MESSAGE_2, SIGNATURE_2, PUBLIC_KEY_2_EXTRA_ENDING_NEWLINE) &&
     not eosio::r1::verify_ecdsa_sig(MESSAGE_2, SIGNATURE_2, PUBLIC_KEY_2_NO_NEWLINES_AT_ALL);
}

int main() {
  for (size_t i = 0; i < 1000; ++i) {
    if (!verify_case_1())  {
      std::cerr << LINE << "\nTest Case 1 Failed\n" << LINE << std::endl;
      return 1;
    }
    if (!verify_case_2()) {
      std::cerr << LINE << "\nTest Case 2 Failed\n" << LINE << std::endl;
      return 2;
    }
  }
  std::cerr << LINE << "\nTest Cases Passed!\n" << LINE << std::endl;
  return 0;
}
