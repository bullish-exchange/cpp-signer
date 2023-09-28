configure_file(${CMAKE_CURRENT_SOURCE_DIR}/api_withdraw_crypto_endpoints.py
               ${CMAKE_CURRENT_BINARY_DIR}/api_withdraw_crypto_endpoints.py COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/create_order.py
               ${CMAKE_CURRENT_BINARY_DIR}/create_order.py COPYONLY)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(Boost 1.71.0 REQUIRED COMPONENTS filesystem)
find_package(OpenSSL REQUIRED)

set(HTTPLIB_IS_USING_OPENSSL TRUE)

include_directories(include)
include_directories(include/rapidjson/include)
include_directories(${Boost_INCLUDE_DIRS})

add_executable(create_order create_order.cpp)
add_executable(ecc_signing ecc_signing.cpp)
add_executable(withdraw withdraw.cpp)

target_compile_definitions(create_order PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT )
target_compile_definitions(withdraw PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT )

target_link_libraries(create_order PRIVATE ${Boost_LIBRARIES})
target_link_libraries(create_order PRIVATE eosio_r1_key)
target_link_libraries(create_order PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(ecc_signing PRIVATE eosio_r1_key)

target_link_libraries(withdraw PRIVATE ${Boost_LIBRARIES})
target_link_libraries(withdraw PRIVATE eosio_r1_key)
target_link_libraries(withdraw PUBLIC OpenSSL::SSL OpenSSL::Crypto)
