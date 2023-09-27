add_library(eosio_r1_key r1_key.cpp crypto.cpp)

target_include_directories(eosio_r1_key PUBLIC "../include" "../library/base64")

target_link_libraries(eosio_r1_key PUBLIC OpenSSL::Crypto base64)
