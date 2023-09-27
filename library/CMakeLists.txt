add_library(base64 base64/base64.cpp)

target_include_directories(base64 PUBLIC "./base64")

if (EOSIO_R1_KEY_ENABLE_BASE64_TEST)
  add_executable(base64_test base64/test.cpp)

  target_include_directories(base64_test PUBLIC "./base64")

  target_link_libraries(base64_test PRIVATE base64)

  add_test(NAME base64_test COMMAND ${CMAKE_CURRENT_BINARY_DIR}/base64_test)
endif()
