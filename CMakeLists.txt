# crackdown2 - ReXGlue Recompiled Project
#
# This file is yours to edit. 'rexglue migrate' will NOT overwrite it.
# SDK boilerplate lives in generated/rexglue.cmake.

cmake_minimum_required(VERSION 3.25)
project(crackdown2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(generated/rexglue.cmake)

# Sources
set(CRACKDOWN2_SOURCES
    src/main.cpp
    src/hooks.cpp
)

if(WIN32)
    add_executable(crackdown2 WIN32 ${CRACKDOWN2_SOURCES})
else()
    add_executable(crackdown2 ${CRACKDOWN2_SOURCES})
endif()

rexglue_setup_target(crackdown2)

