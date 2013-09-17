set(TARGET rubyssl)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(${CMAKE_BINARY_DIR})
link_directories(${CMAKE_SOURCE_DIR}/../libs/)

set(HEADERS
)


set(SOURCES
    main.c
)

set(DEPS
)

add_library(${TARGET} SHARED ${HEADERS} ${SOURCES})
target_link_libraries(${TARGET} ${DEPS} libssl.a libcrypto.a)

add_executable(${TARGET}_test WIN32 ${HEADERS} ${SOURCES})
target_link_libraries(${TARGET}_test ${DEPS} libssl.a libcrypto.a)
