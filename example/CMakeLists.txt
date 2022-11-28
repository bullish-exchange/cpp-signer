
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/create_order.py ${CMAKE_CURRENT_BINARY_DIR}/create_order.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/api_withdraw_crypto_endpoints.py ${CMAKE_CURRENT_BINARY_DIR}/api_withdraw_crypto_endpoints.py COPYONLY)
add_executable(ecc_signing ecc_signing.cpp)
target_link_libraries(ecc_signing PRIVATE eosio_r1_key)