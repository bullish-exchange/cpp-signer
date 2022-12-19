
#include "httplib/httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <eosio/r1_key.hpp>

#include <boost/beast/core/detail/base64.hpp>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>


struct Env {
  std::string hostname;
  std::string private_key;
  std::string encoded_metadata;
};

struct Meta {
  std::string account_id;
  std::string public_key;
  std::string credential_id;
};

bool getenv(std::string &str, const char *name) {
  if (const char *p = std::getenv(name)) {
    str.assign(p);
    return true;
  }
  std::cerr << "Error: Variable \"" << name << "\" not set in the environment."
            << std::endl;
  return false;
}

bool load_env(Env &env) {
  return getenv(env.hostname, "BX_API_HOSTNAME") &&
         getenv(env.private_key, "BX_PRIVATE_KEY") &&
         getenv(env.encoded_metadata, "BX_API_METADATA");
}


bool check_key(const rapidjson::Document &d, const char *key) {
  if (!d.HasMember(key)) {
    std::cerr << "Error: Key \"" << key << "\" not found in JSON string."
              << std::endl;
    return false;
  }
  if (!d[key].IsString()) {
      std::cerr << "Error: Key \"" << key << "\" found in JSON string "
                   "but its value is not a string." << std::endl;
      return false;
  }
  return true;
}

bool load_value(std::string &value, const char* key, const char* json) {
  rapidjson::Document d;
  d.Parse(json);
  if (!check_key(d, key)) {
    return false;
  }
  value = d[key].GetString();
  return true;
}

bool load_meta(Meta &meta, const char* json) {
   return load_value(meta.account_id, "accountId", json) &&
          load_value(meta.public_key, "publicKey", json) &&
          load_value(meta.credential_id, "credentialId", json);
}


int get_time_now() {
  // e.g. return 1669796089;
  return std::time(nullptr);
}

void print_step(const std::string &step) {
  std::cout << "\n=== STEP " + step + " " + std::string(90 - step.size(), '=') << "\n" << std::endl;
}

int main() {
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

  // STEP 0. Load Environment Variables
  print_step("0. Load Environment Variables");

  Env env;
  if (!load_env(env)) {
    std::cerr << "Please make sure the environment variables have been set:\n"
                  "  - BX_API_HOSTNAME\n"
                  "  - BX_PRIVATE_KEY\n"
                  "  - BX_API_METADATA" << std::endl;;
    return 1;
  }

  std::string hidden = std::string(env.private_key.size(), '*');
  std::cout << "% Loaded BX_API_HOSTNAME: " << env.hostname << std::endl;
  std::cout << "% Loaded BX_PRIVATE_KEY: " << hidden << std::endl;
  std::cout << "% Loaded BX_API_METADATA: " << env.encoded_metadata << std::endl;

  // an example of expected decoded_json:
  // {
  //   "accountId": "222000000000047",
  //   "publicKey": "PUB_R1_7YTbnWCo44r32n8avMdLPf5gGp8hUwQb4bxFYoXgnSsCB9YZny",
  //   "credentialId": "118"
  // }

  std::string decoded_json;
  decoded_json.resize(boost::beast::detail::base64::decoded_size(env.encoded_metadata.size()));
  boost::beast::detail::base64::decode(decoded_json.data(),
                                       env.encoded_metadata.data(),
                                       env.encoded_metadata.size());

  std::cout << decoded_json << std::endl;

  Meta meta;
  if (!load_meta(meta, decoded_json.c_str())) {
    std::cerr << "Error: Cannot load decoded metadata." << std::endl;
    std::cerr << "JSON decoded from BX_API_METADATA: " << decoded_json << std::endl;
    return 1;
  }
  std::cout << "% Loaded from BX_API_METADATA accountId: " << meta.account_id << std::endl;
  std::cout << "% Loaded from BX_API_METADATA publicKey: " << meta.public_key << std::endl;
  std::cout << "% Loaded from BX_API_METADATA credentialId: " << meta.credential_id << std::endl;

  // STEP 1. Login
  print_step("1. Login");
  int timestamp = get_time_now();
  int expiration_time = timestamp + 300;
  std::string nonce = std::to_string(timestamp);
  std::string payload = "{"
    "\"accountId\":\"" + meta.account_id + "\","
    "\"nonce\":" + nonce + ","
    "\"expirationTime\":" + std::to_string(expiration_time) + ","
    "\"biometricsUsed\":false,"
    "\"sessionKey\":null"
  "}";

  eosio::r1::private_key priv_key{env.private_key};
  std::string signature = priv_key.sign(payload);

  std::cout << "% signature: " << signature << std::endl;

  std::string body = "{"
    "\"publicKey\":\"" + meta.public_key + "\","
    "\"signature\":\"" + signature + "\","
    "\"loginPayload\":" + payload +
  "}";
  httplib::Client cli(env.hostname);
  std::string path = "/trading-api/v1/users/login";
  std::string content_type = "application/json";
  std::cout << "% Sending HTTP request to: "<< (env.hostname + path) << std::endl;
  std::cout << "% Sending HTTP request with body: " << body << std::endl;
  httplib::Result res = cli.Post(path, body, content_type);
  std::string response = res->body;
  std::cout << "% Received HTTP response status code: " << res->status << std::endl;
  std::cout << "% Received HTTP response body: " << response << std::endl;
  std::string token;
  if (!load_value(token, "token", response.c_str())) {
    std::cerr << "Error: Cannot load token from HTTP response." << std::endl;
    return 1;
  }
  std::cout << "% Token: " << token << std::endl;

  // STEP 2. Withdrawal Challenge
  print_step("2. Withdrawal Challenge");
  timestamp = get_time_now();
  nonce = std::to_string(timestamp);
  body = "{"
    "\"nonce\":\"" + nonce + "\","
    "\"command\":{"
      "\"commandType\":\"V1WithdrawalChallenge\","
      "\"destinationId\":\"bf6d41a97a1d56e289cdaf10f386a3bd5166d51f9edf50892874bf2e7c0ddaf4\","
      "\"network\":\"SWIFT\","
      "\"symbol\":\"USD\","
      "\"quantity\":\"1\""
    "}"
  "}";
  httplib::Headers headers = { { "Authorization", "Bearer " + token } };
  path ="/trading-api/v1/wallets/withdrawal-challenge";
  std::cout << "% Sending HTTP request to: "<< (env.hostname + path) << std::endl;
  std::cout << "% Sending HTTP request with body: " << body << std::endl;
  res = cli.Post(path, headers, body, content_type);
  response = res->body;
  std::cout << "% Received HTTP response status code: " << res->status << std::endl;
  std::cout << "% Received HTTP response body: " << response << std::endl;
  std::string challenge;
  if (!load_value(challenge, "challenge", response.c_str())) {
    std::cerr << "Error: Cannot load challenge from response." << std::endl;
    return 1;
  }
  std::cout << "% Challenge: " << challenge << std::endl;

  // Step 3. Withdrawal Assertion
  print_step("3. Withdrawal Assertion");
  signature = priv_key.sign_digest(challenge);
  std::cout << "% Signature: " << signature << std::endl;
  body = "{"
    "\"command\":{"
      "\"commandType\":\"V1WithdrawalAssertion\","
      "\"signature\":\"" + signature + "\","
      "\"challenge\":\"" + challenge + "\","
      "\"publicKey\":\"" + meta.public_key + "\""
    "}"
  "}";
  path = "/trading-api/v1/wallets/withdrawal-assertion";
  std::cout << "% Sending HTTP request to "<< (env.hostname + path) << std::endl;
  std::cout << "% Sending HTTP request with body: " << body << std::endl;
  res = cli.Post(path, headers, body, content_type);
  response = res->body;
  std::cout << "% Received HTTP response status code: " << res->status << std::endl;
  std::cout << "% Received HTTP response body: " << response << std::endl;
  return 0;
}
