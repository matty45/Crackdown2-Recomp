# Builds tracy-sampdump against the Tracy server library vendored in the rexglue
# SDK source tree (thirdparty/tracy). Usage:
#   cmake -S tools/tracy_sampdump -B build-sampdump -DTRACY_ROOT=/path/to/rexglue-sdk/thirdparty/tracy
#   cmake --build build-sampdump
#   build-sampdump/tracy-sampdump capture.tracy [topN]
cmake_minimum_required(VERSION 3.16)
option(NO_ISA_EXTENSIONS "" ON)
set(NO_STATISTICS OFF)
set(TRACY_ROOT "" CACHE PATH "Path to Tracy source (rexglue-sdk/thirdparty/tracy)")
if(NOT TRACY_ROOT)
  message(FATAL_ERROR "Set -DTRACY_ROOT=<rexglue-sdk>/thirdparty/tracy")
endif()
include(${TRACY_ROOT}/cmake/version.cmake)
set(CMAKE_CXX_STANDARD 20)
project(tracy-sampdump LANGUAGES C CXX VERSION ${TRACY_VERSION_STRING})
include(${TRACY_ROOT}/cmake/config.cmake)
include(${TRACY_ROOT}/cmake/vendor.cmake)
include(${TRACY_ROOT}/cmake/server.cmake)
add_executable(${PROJECT_NAME} sampdump.cpp ${COMMON_FILES} ${SERVER_FILES})
target_include_directories(${PROJECT_NAME} PRIVATE ${TRACY_ROOT})
target_link_libraries(${PROJECT_NAME} PRIVATE TracyServer)
