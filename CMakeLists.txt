set(TARGET sslgem)
project(${TARGET})

cmake_minimum_required(VERSION 2.4)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(IMAGE_DIR ${CMAKE_BINARY_DIR}/image) 

add_subdirectory(openssl_src EXCLUDE_FROM_ALL)
add_subdirectory(rubyssl_src EXCLUDE_FROM_ALL)

add_custom_target(ssl DEPENDS libopenssl)

add_custom_target(ruby DEPENDS ssl DEPENDS rubyssl)

set(GEM_DIR ${CMAKE_BINARY_DIR}/gem)
add_custom_target(gem DEPENDS rubyssl
	COMMAND cp -rf ${CMAKE_SOURCE_DIR}/gem ${CMAKE_BINARY_DIR}
	COMMAND mv ${IMAGE_DIR} ${GEM_DIR}/lib/
	COMMAND cd ${GEM_DIR} && gem build sslgem.gemspec
	COMMAND mv ${GEM_DIR}/lib/image ${IMAGE_DIR})

