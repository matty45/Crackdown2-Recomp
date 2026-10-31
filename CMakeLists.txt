# crackdown2 - ReXGlue Recompiled Project
#
# This file is yours to edit. 'rexglue migrate' will NOT overwrite it.
# SDK boilerplate lives in generated/rexglue.cmake.

cmake_minimum_required(VERSION 3.25)
project(crackdown2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Cross builds (Android) cannot build the codegen tool, but generated/rexglue.cmake
# still runs it as a host step whenever the manifest or its inputs change. Point
# REXGLUE_HOST_TOOL at a host build of the rexglue CLI (an installed SDK's
# bin/rexglue works).
if(CMAKE_CROSSCOMPILING AND NOT TARGET rex::rexglue)
    set(REXGLUE_HOST_TOOL "" CACHE FILEPATH "Host rexglue CLI used for codegen when cross-compiling")
    if(NOT REXGLUE_HOST_TOOL OR NOT EXISTS "${REXGLUE_HOST_TOOL}")
        message(FATAL_ERROR "Cross-compiling: set REXGLUE_HOST_TOOL to a host rexglue executable")
    endif()
    add_executable(rex::rexglue IMPORTED)
    set_target_properties(rex::rexglue PROPERTIES IMPORTED_LOCATION "${REXGLUE_HOST_TOOL}")
endif()

include(generated/rexglue.cmake)

# rexglue 0.10.0 ignores [analysis] max_jump_table_entries from the manifest
# (fixed by SDK patch 0005, not in the prebuilt tool), and the animation
# attribute loader needs a 519-entry switch table: with the default cap of 512
# it traps on attribute ids 512-517 while loading the game database. Run the
# codegen tool through a wrapper that sets REX_MAX_JUMP_TABLE_ENTRIES=519 so
# every build regenerates correct code. (generated/rexglue.cmake is codegen
# output, so this lives here.)
if(TARGET rex::rexglue)
    get_target_property(_rexglue_imported rex::rexglue IMPORTED)
    if(_rexglue_imported)
        get_target_property(_rexglue_real rex::rexglue IMPORTED_LOCATION_RELEASE)
        if(NOT _rexglue_real)
            get_target_property(_rexglue_real rex::rexglue IMPORTED_LOCATION)
        endif()
        if(_rexglue_real AND NOT _rexglue_real MATCHES "rexglue_codegen_wrapper")
            if(CMAKE_HOST_WIN32)
                file(TO_NATIVE_PATH "${_rexglue_real}" _rexglue_real_native)
                set(_rexglue_wrapper "${CMAKE_BINARY_DIR}/rexglue_codegen_wrapper.cmd")
                file(WRITE "${_rexglue_wrapper}"
                     "@echo off\r\nset REX_MAX_JUMP_TABLE_ENTRIES=519\r\n\"${_rexglue_real_native}\" %*\r\n")
            else()
                set(_rexglue_wrapper "${CMAKE_BINARY_DIR}/rexglue_codegen_wrapper.sh")
                file(WRITE "${_rexglue_wrapper}"
                     "#!/bin/sh\nREX_MAX_JUMP_TABLE_ENTRIES=519 exec \"${_rexglue_real}\" \"$@\"\n")
                file(CHMOD "${_rexglue_wrapper}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
            endif()
            set_target_properties(rex::rexglue PROPERTIES
                IMPORTED_LOCATION "${_rexglue_wrapper}"
                IMPORTED_LOCATION_RELEASE "${_rexglue_wrapper}")
        endif()
    endif()
endif()

# Sources
set(CRACKDOWN2_SOURCES
    src/main.cpp
    src/hooks.cpp
    src/native_menu.cpp
    src/game_console.cpp
    src/profiling.cpp
)

if(WIN32)
    add_executable(crackdown2 WIN32 ${CRACKDOWN2_SOURCES})
elseif(ANDROID)
    # SDLActivity loads libmain.so and calls its SDL_main; the generated code
    # and the SDK runtime come along as shared libraries in the APK.
    add_library(crackdown2 SHARED ${CRACKDOWN2_SOURCES})
    set_target_properties(crackdown2 PROPERTIES OUTPUT_NAME main)
else()
    add_executable(crackdown2 ${CRACKDOWN2_SOURCES})
endif()

rexglue_setup_target(crackdown2 GPU_PLUGINS xenos)

# In-tree SDK builds (Android) do not export the ImGui/RenderDoc include
# directories that rex/rex_app.h needs; the installed SDK ships them.
if(TARGET imgui)
    target_link_libraries(crackdown2 PRIVATE imgui::imgui)
endif()
if(TARGET renderdoc)
    target_link_libraries(crackdown2 PRIVATE renderdoc)
endif()


# Windows application/taskbar icon (resources/crackdown2.rc -> crackdown2.ico).
if(WIN32)
    enable_language(RC)
    target_sources(crackdown2 PRIVATE resources/crackdown2.rc)
endif()
