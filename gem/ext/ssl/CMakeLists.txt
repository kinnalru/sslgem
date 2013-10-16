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
add_subdirectory(sslext_src EXCLUDE_FROM_ALL)

add_custom_target(ssl DEPENDS libopenssl)

add_custom_target(ext DEPENDS ssl DEPENDS sslext DEPENDS sslext_test)

#set(GEM_DIR ${CMAKE_BINARY_DIR}/gem)
#add_custom_target(gem DEPENDS ssl DEPENDS ruby
#	COMMAND cp -rf ${CMAKE_SOURCE_DIR}/gem ${CMAKE_BINARY_DIR}
#	COMMAND mv ${IMAGE_DIR} ${GEM_DIR}/lib/
#	COMMAND cd ${GEM_DIR} && gem build sslgem.gemspec
#	COMMAND cd ${GEM_DIR} && gem generate_index
#	COMMAND mv ${GEM_DIR}/lib/image ${IMAGE_DIR})

#add_custom_target(all DEPENDS gem)
