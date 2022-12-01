
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/create_order.py ${CMAKE_CURRENT_BINARY_DIR}/create_order.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/api_withdraw_crypto_endpoints.py ${CMAKE_CURRENT_BINARY_DIR}/api_withdraw_crypto_endpoints.py COPYONLY)

add_executable(ecc_signing ecc_signing.cpp)

add_executable(withdraw withdraw.cpp)

target_link_libraries(ecc_signing PRIVATE eosio_r1_key)


include_directories(include)
include_directories(include/rapidjson/include)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(HTTPLIB_IS_USING_OPENSSL TRUE)
endif()

target_link_libraries(withdraw PUBLIC
        $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::SSL>
        $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:OpenSSL::Crypto>)

target_compile_definitions(withdraw PUBLIC
        $<$<BOOL:${HTTPLIB_IS_USING_OPENSSL}>:CPPHTTPLIB_OPENSSL_SUPPORT>
        )

target_link_libraries(withdraw PRIVATE eosio_r1_key)

find_package(Boost 1.71.0 COMPONENTS *boost libraries here*)
include_directories(${Boost_INCLUDE_DIRS})
target_link_libraries(withdraw ${Boost_LIBRARIES})


