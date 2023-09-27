cmake_minimum_required (VERSION 3.10)

# This is your project statement. You should always list languages;
# Listing the version is nice here since it sets lots of useful variables
project(eosio_r1_key VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_FLAGS "-Wno-deprecated-declarations")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
endif()

find_package(OpenSSL REQUIRED)

if (EOSIO_R1_KEY_ENABLE_BASE64_TEST)
    enable_testing()
endif()

add_subdirectory(library)
add_subdirectory(src)

option(EOSIO_R1_KEY_ENABLE_TEST "Enable building test" OFF)
option(EOSIO_R1_KEY_ENABLE_EXAMPLE "Enable building example" OFF)

if (EOSIO_R1_KEY_ENABLE_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()

if (EOSIO_R1_KEY_ENABLE_EXAMPLE)
    add_subdirectory(example)
endif()
