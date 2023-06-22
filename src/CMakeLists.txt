
add_library(eosio_r1_key r1_key.cpp crypto.cpp)
target_include_directories(eosio_r1_key PUBLIC 
   "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../include;" 
   "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
target_link_libraries(eosio_r1_key PUBLIC OpenSSL::Crypto)

