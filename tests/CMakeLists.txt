add_executable(sign_test sign_test.cpp)
add_executable(verify_test verify_test.cpp)

target_link_libraries(sign_test PRIVATE eosio_r1_key base64)
target_link_libraries(verify_test PRIVATE eosio_r1_key base64)

add_test(NAME sign_test COMMAND ${CMAKE_CURRENT_BINARY_DIR}/sign_test)
add_test(NAME verify_test COMMAND ${CMAKE_CURRENT_BINARY_DIR}/verify_test)
