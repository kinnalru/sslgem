set(TARGET ssllibs)
project(${TARGET})

cmake_minimum_required(VERSION 2.4)
if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if (DEFINED DESTDIR)
	message("DESTDIR=[${DESTDIR}]")
else()
	set(DESTDIR ${CMAKE_BINARY_DIR}) 
	message("DESTDIR=[${DESTDIR}]")
endif()

set(IMAGE_DIR ${DESTDIR}/image) 


add_subdirectory(openssl_src EXCLUDE_FROM_ALL)
add_custom_target(ssl DEPENDS libopenssl)

add_custom_target(ext DEPENDS ssl
    COMMAND cd "${CMAKE_CURRENT_SOURCE_DIR}/sslext_src" && IMAGE_DIR="${IMAGE_DIR}" ruby extconf.rb
    COMMAND cd "${CMAKE_CURRENT_SOURCE_DIR}/sslext_src" && make && cp *.so "${IMAGE_DIR}/lib/"
)

add_custom_target(all DEPENDS ext)
