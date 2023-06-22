
add_executable(sign_test sign_test.cpp)
target_link_libraries(sign_test PRIVATE eosio_r1_key)
add_test(NAME sign_test COMMAND ${CMAKE_CURRENT_BINARY_DIR}/sign_test)