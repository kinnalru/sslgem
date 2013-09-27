set(TARGET rubyssl)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/openssl_src/)
link_directories(${CMAKE_BINARY_DIR}/lib/)
link_directories(${IMAGE_DIR}/lib/)

add_definitions(-DMONOLITH)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${IMAGE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${IMAGE_DIR}/lib)

set(HEADERS
)


set(SOURCES
    main.cpp
)

set(DEPS
	openssl ssl crypto dl
)



add_library(${TARGET} SHARED ${HEADERS} ${SOURCES})
target_link_libraries(${TARGET} ${DEPS})

add_executable(${TARGET}_test WIN32 ${HEADERS} ${SOURCES})
target_link_libraries(${TARGET}_test ${DEPS})
