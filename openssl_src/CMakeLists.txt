set(TARGET libopenssl)
project(${TARGET})

cmake_minimum_required(VERSION 2.4)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set(LOCAL_PREFIX ${IMAGE_DIR})

include(ExternalProject)
ExternalProject_Add(
   libopenssl_build
   SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
   PREFIX ${LOCAL_PREFIX}
   CONFIGURE_COMMAND ./build_openssl.sh ${LOCAL_PREFIX}
   BUILD_IN_SOURCE 1
)


add_custom_target(libopenssl DEPENDS libopenssl_build
	COMMAND cp -rf ${CMAKE_CURRENT_SOURCE_DIR}/apps/libopenssl.so ${IMAGE_DIR}/lib
	COMMAND cp -rf ${CMAKE_CURRENT_SOURCE_DIR}/apps/libopenssl.a ${IMAGE_DIR}/lib)

