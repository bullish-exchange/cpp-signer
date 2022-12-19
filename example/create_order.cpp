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
  std::string jwt_token;
  std::string authorizer;
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
         getenv(env.jwt_token, "BX_JWT") &&
         getenv(env.authorizer, "BX_AUTHORIZER");
}

bool check_key_u64(const rapidjson::Document &d, const char *key) {
  if (!d.HasMember(key)) {
    std::cerr << "Error: Key \"" << key << "\" not found in JSON string."
              << std::endl;
    return false;
  }
  if (!d[key].IsUint64()) {
    std::cerr << "Error: Key \"" << key
              << "\" found in JSON string "
                 "but its value is not an unsigned 64-bit integer."
              << std::endl;
    return false;
  }
  return true;
}

bool load_u64(uint64_t &u64, const char *key, const char *json) {
  rapidjson::Document d;
  d.Parse(json);
  if (!check_key_u64(d, key)) {
    return false;
  }
  u64 = d[key].GetUint64();
  return true;
}

uint64_t get_time_now_u64() {
  // return number of seconds since epoch (1 Jan 1970 UTC)
  // e.g. return 1669796089;
  return static_cast<uint64_t>(std::time(nullptr));
}

void print_step(const std::string &step) {
  std::cout << "\n=== STEP " + step + " " + std::string(90 - step.size(), '=')
            << "\n"
            << std::endl;
}

std::string headers_to_string(const httplib::Headers &headers) {
  std::ostringstream oss;
  oss << "\n--- Headers -----\n";
  for (const std::pair<std::string, std::string> &pa : headers) {
    if (pa.first == "Authorization") {
      oss << pa.first << ": [--- HIDDEN ---]" << std::endl;
    } else {
      oss << pa.first << ": " << pa.second << std::endl;
    }
  }
  oss << "-----------------\n";
  return oss.str();
}

void print_request(const std::string &addr, const std::string &body = "",
                   const httplib::Headers &headers = httplib::Headers{}) {
  std::cout << "% Sending HTTP request to: " << addr << std::endl;
  if (!headers.empty()) {
    std::cout << "% Sending HTTP request with headers: "
              << headers_to_string(headers);
  }
  if (!body.empty()) {
    std::cout << "% Sending HTTP request with body: " << body << std::endl;
  }
}

void print_response(const httplib::Result &res) {
  std::cout << "% Received HTTP response status code: " << res->status
            << std::endl;
  std::cout << "% Received HTTP response reason: " << res->reason << std::endl;
  std::cout << "% Received HTTP response body: " << res->body << std::endl;
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
                 "  - BX_JWT\n"
                 "  - BX_AUTHORIZER\n"
              << std::endl;
    ;
    return 1;
  }

  std::string hidden = "[--- HIDDEN ---]";
  std::cout << "% Loaded BX_API_HOSTNAME: " << env.hostname << std::endl;
  std::cout << "% Loaded BX_PRIVATE_KEY: " << hidden << std::endl;
  std::cout << "% Loaded BX_JWT: " << hidden << std::endl;
  std::cout << "% Loaded BX_AUTHORIZER: " << env.authorizer << std::endl;

  // STEP 1. Get Nonce
  print_step("1. Get Nonce");
  httplib::Client cli(env.hostname);
  std::string path;
  std::string body;
  std::string signature;
  path = "/trading-api/v1/nonce";
  httplib::Result res = cli.Get(path);
  print_request(env.hostname + path);
  print_response(res);
  uint64_t nonce_u64;
  if (!load_u64(nonce_u64, "lowerBound", res->body.c_str())) {
    std::cerr << "Error: Cannot load lowerBound of nonce from HTTP response."
              << std::endl;
    return 1;
  }
  nonce_u64 += 1;
  std::cout << "% Nonce: " << nonce_u64 << std::endl;
  std::string nonce = std::to_string(nonce_u64);

  // STEP 2. Create Order
  print_step("2. Create Order");
  uint64_t timestamp_u64 = get_time_now_u64();
  std::string timestamp = std::to_string(timestamp_u64) + "000";
  body = "{"
         "\"timestamp\":\"" +
         timestamp +
         "\","
         "\"nonce\":\"" +
         nonce +
         "\","
         "\"authorizer\":\"" +
         env.authorizer +
         "\","
         "\"command\":{"
         "\"commandType\":\"V1CreateOrder\","
         "\"handle\":null,"
         "\"symbol\":\"BTCUSD\","
         "\"type\":\"LMT\","
         "\"side\":\"BUY\","
         "\"price\":\"30071.5000\","
         "\"stopPrice\":null,"
         "\"quantity\":\"1.87000000\","
         "\"timeInForce\":\"GTC\","
         "\"allowMargin\":false"
         "}"
         "}";
  eosio::r1::private_key priv_key{env.private_key};
  signature = priv_key.sign(body);
  std::cout << "% Signature: " << signature << std::endl;
  httplib::Headers headers = {{"Authorization", "Bearer " + env.jwt_token},
                              {"BX-SIGNATURE", signature},
                              {"BX-TIMESTAMP", timestamp},
                              {"BX-NONCE", nonce}};
  path = "/trading-api/v1/orders";
  print_request(env.hostname + path, body, headers);
  std::string content_type = "application/json";
  res = cli.Post(path, headers, body, content_type);
  print_response(res);
  return 0;
}
