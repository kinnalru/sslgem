set(TARGET sslgem)
project(${TARGET})

cmake_minimum_required(VERSION 2.4)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_subdirectory(openssl_src EXCLUDE_FROM_ALL)
add_subdirectory(rubyssl_src EXCLUDE_FROM_ALL)

add_custom_target(ssl DEPENDS libopenssl
	COMMAND mkdir -p image
	COMMAND cp ${CMAKE_BINARY_DIR}/lib/*.a image
	COMMAND cp ${CMAKE_BINARY_DIR}/bin/* image)

add_custom_target(ruby DEPENDS ssl rubyssl
	COMMAND mkdir -p image
	COMMAND cp ${CMAKE_BINARY_DIR}/lib/*.so image)

add_custom_target(gem DEPENDS rubyssl
	COMMAND mkdir -p image
	COMMAND cp image/librubyssl.so ${CMAKE_SOURCE_DIR}/gem/lib
	COMMAND cd ${CMAKE_SOURCE_DIR}/gem && gem build sslgem.gemspec
	COMMAND cp ${CMAKE_SOURCE_DIR}/gem/lib/*.rb image
	COMMAND cp ${CMAKE_SOURCE_DIR}/gem/*.gem image)

