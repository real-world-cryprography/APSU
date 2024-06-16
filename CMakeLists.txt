# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

###################################################
# Project APSU includes the following components: #
#   1. APSU C++ library that includes             #
#      1) common API                              #
#      2) sender API                              #
#      3) receiver API                            #
#   2. APSU unit tests                            #
#   3. APSU integration tests                     #
#   4. APSU command line interface                #
###################################################

# [option] CMAKE_BUILD_TYPE (default: "Release")
# Build in one of the following modes: Release, Debug, MiniSizeRel, or RelWithDebInfo.
# Most generators recognize these and can set the compiler flags accordingly. We set
# the build type here before creating the project to prevent the CMake generator from
# overriding our default of "Release".




if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

project(APSU VERSION 0.7.0 LANGUAGES CXX C)

# This policy was introduced in CMake 3.13; OLD by default until CMake 3.21
cmake_policy(SET CMP0077 NEW)

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceRuns)
include(CheckLanguage)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(APSUMacros)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

# In Debug mode, define APSU_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(APSU_DEBUG ON)
    # In Debug mode, enable extra compiler flags.
    include(EnableCXXCompilerFlags)
else()
    set(APSU_DEBUG OFF)
endif()
message(STATUS "APSU debug mode: ${APSU_DEBUG}")

# [option] APSU_USE_CXX17_OPTION_STR (default: ON)
# Use C++17, use C++14 otherwise. An error will be thrown if SEAL_USE_CXX17 is ON but APSU_USE_CXX17 is OFF.
set(APSU_USE_CXX17_OPTION_STR "Use C++17")
option(APSU_USE_CXX17 ${APSU_USE_CXX17_OPTION_STR} ON)
message(STATUS "APSU_USE_CXX17: ${APSU_USE_CXX17}")

# Enable security-related compile options (MSVC only)
set(APSU_SECURE_COMPILE_OPTIONS_OPTION_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(APSU_SECURE_COMPILE_OPTIONS ${APSU_SECURE_COMPILE_OPTIONS_OPTION_STR} OFF)
mark_as_advanced(APSU_SECURE_COMPILE_OPTIONS)

# Path for output
set(OUTLIB_PATH "lib")

# Required files and directories
include(GNUInstallDirs)

# Source tree
set(APSU_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/APSUConfig.cmake.in)
set(APSU_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR})
set(APSU_CONFIG_H_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/common/apsu/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(APSU_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(APSU_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSUTargets.cmake)
set(APSU_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSUConfig.cmake)
set(APSU_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/APSUConfigVersion.cmake)
set(APSU_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/common/apsu/config.h)

# Install
set(APSU_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/APSU-${APSU_VERSION_MAJOR}.${APSU_VERSION_MINOR})
set(APSU_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/APSU-${APSU_VERSION_MAJOR}.${APSU_VERSION_MINOR})

# pkg-config
# TODO: not provided yet

#########################
# External Dependencies #
#########################
# All dependencies are assumed pre-installed.
# find_package might throw a FATAL_ERROR before"xxx: not found", e.g. with vcpkg.cmake.

# OPENSSL
# set(OPENSSL_USE_STATIC_LIBS True)
find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)


# Microsoft SEAL
find_package(SEAL QUIET REQUIRED)
if(NOT SEAL_FOUND)
    message(FATAL_ERROR "Microsoft SEAL: not found")
else()
    message(STATUS "Microsoft SEAL: found")
endif()
if(NOT APSU_USE_CXX17 AND SEAL_USE_CXX17)
    message(FATAL_ERROR "CXX standards mismatch: APSU_USE_CXX17 is OFF, SEAL_USE_CXX17 is ON")
endif()

# Microsoft Kuku
find_package(Kuku 2.1 QUIET REQUIRED)
if(NOT Kuku_FOUND)
    message(FATAL_ERROR "Microsoft Kuku: not found")
else()
    message(STATUS "Microsoft Kuku: found")
endif()

# Flatbuffers
find_package(Flatbuffers REQUIRED)
if(NOT Flatbuffers_FOUND)
    message(FATAL_ERROR "Flatbuffers: not found")
else()
    message(STATUS "Flatbuffers: found")
    get_target_property(FLATBUFFERS_FLATC_PATH flatbuffers::flatc IMPORTED_LOCATION_RELEASE)
    message(STATUS "flatc path: ${FLATBUFFERS_FLATC_PATH}")
    include(CompileSchemaCXX)
endif()

# jsoncpp: for parameter configuration
find_package(jsoncpp REQUIRED)
if (NOT jsoncpp_FOUND)
    message(FATAL_ERROR "jsoncpp: not found")
else()
    message(STATUS "jsoncpp: found")
endif()



# [Option] APSU_USE_LOG4CPLUS (default: ON)
set(APSU_USE_LOG4CPLUS_OPTION_STR "Use Log4cplus for logging")
option(APSU_USE_LOG4CPLUS ${APSU_USE_LOG4CPLUS_OPTION_STR} ON)
if(APSU_USE_LOG4CPLUS)
    # Log4cplus
    find_package(log4cplus REQUIRED)
    if(NOT log4cplus_FOUND)
        message(FATAL_ERROR "log4cplus: not found")
    else()
        message(STATUS "log4cplus: found")
    endif()
endif()

# [Option] APSU_USE_ZMQ (default: ON)
set(APSU_USE_ZMQ_OPTION_STR "Use ZeroMQ for networking")
option(APSU_USE_ZMQ ${APSU_USE_ZMQ_OPTION_STR} ON)
if(APSU_USE_ZMQ)
    # ZeroMQ base
    find_package(ZeroMQ REQUIRED)
    if(NOT ZeroMQ_FOUND)
        message(FATAL_ERROR "ZeroMQ: not found")
    else()
        message(STATUS "ZeroMQ: found")
    endif()
    # cppzmq wrapper
    find_package(cppzmq REQUIRED)
    if(NOT cppzmq_FOUND)
        message(FATAL_ERROR "cppzmq: not found")
    else()
        message(STATUS "cppzmq: found")
    endif()
endif()

# [Option] APSU_BUILD_CLI (default: OFF)
set(APSU_BUILD_CLI_OPTION_STR "Build example command line interface applications")
cmake_dependent_option(APSU_BUILD_CLI ${APSU_BUILD_CLI_OPTION_STR} OFF "APSU_USE_ZMQ;APSU_USE_LOG4CPLUS" OFF)
if (APSU_BUILD_CLI)
    # TCLAP
    find_path(TCLAP_INCLUDE_DIRS "tclap/Arg.h")
    if(TCLAP_INCLUDE_DIRS STREQUAL "TCLAP_INCLUDE_DIRS-NOTFOUND")
        message(FATAL_ERROR "TCLAP: not found")
    else()
        message(STATUS "TCLAP: found")
        message(STATUS "TCLAP_INCLUDE_DIRS: ${TCLAP_INCLUDE_DIRS}")
    endif()
endif()

####################
# libOTe build     #
####################
if(NOT LIBOTE_PATH)
    set(LIBOTE_PATH "${CMAKE_SOURCE_DIR}/thirdparty")
endif()
message(STATUS "LIBOTE_PATH :${LIBOTE_PATH}")
find_package(libOTe REQUIRED HINTS "${LIBOTE_PATH}" )
if(NOT libOTe_FOUND)
    message(FATAL_ERROR "LibOTe: not found")
else()
    message(STATUS "LIBOTE version ${libOTe_VERSION_MAJOR}.${libOTe_VERSION_MINOR}.${libOTe_VERSION_PATCH}")
endif()
####################
# Kunlun build     #
####################

include_directories(${CMAKE_SOURCE_DIR})


####################
# APSU C++ library #
####################

# [option] BUILD_SHARED_LIBS (default: OFF)
# Build a shared library if set to ON. Build a static library regardlessly.
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
# TODO: consider building shared in future
if(BUILD_SHARED_LIBS)
    message(FATAL_ERROR "Only static build is supported; set `BUILD_SHARED_LIBS=OFF`")
endif()

# Create the config file
configure_file(${APSU_CONFIG_H_IN_FILENAME} ${APSU_CONFIG_H_FILENAME})
install(
    FILES ${APSU_CONFIG_H_FILENAME}
    DESTINATION ${APSU_INCLUDES_INSTALL_DIR}/apsu)

# Create a single library "apsu" for common, sender, and receiver


message(STATUS "APSU_USE_Kunlun")


add_executable(sender_cli_osn)
add_executable(receiver_cli_osn)
add_executable(sender_cli_ddh)
add_executable(receiver_cli_ddh)

########  target include for sender cli  #########
target_include_directories(sender_cli_osn PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/common>
    )
target_include_directories(sender_cli_osn PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/sender>
    )
target_include_directories(sender_cli_osn PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common>
    )
target_include_directories(sender_cli_osn PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/sender>
    )

target_include_directories(sender_cli_ddh PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/common>
    )
target_include_directories(sender_cli_ddh PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/sender>
    )
target_include_directories(sender_cli_ddh PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common>
    )
target_include_directories(sender_cli_ddh PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/sender>
    )


########  target include for receiver cli  #########

target_include_directories(receiver_cli_osn PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/common>
)
target_include_directories(receiver_cli_osn PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/receiver>
)
target_include_directories(receiver_cli_osn PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common>
)
target_include_directories(receiver_cli_osn PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/receiver>
)

target_include_directories(receiver_cli_ddh PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/common>
)
target_include_directories(receiver_cli_ddh PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/receiver>
)
target_include_directories(receiver_cli_ddh PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/common>
)
target_include_directories(receiver_cli_ddh PUBLIC
$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/receiver>
)


SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-pic -Wno-deprecated-declarations -Xpreprocessor -fopenmp -pthread -O3 -fPIE")

##### target cli for sender #########

target_link_libraries(sender_cli_osn
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
TARGET_LINK_LIBRARIES(sender_cli_osn PUBLIC ${OPENSSL_LIBRARIES})
target_link_libraries(sender_cli_osn PUBLIC oc::libOTe)


target_compile_options(sender_cli_osn PRIVATE "-mavx2" "-maes" "-msse2")
target_link_libraries(sender_cli_osn PUBLIC OpenMP::OpenMP_CXX)

target_link_libraries(sender_cli_ddh
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
TARGET_LINK_LIBRARIES(sender_cli_ddh PUBLIC ${OPENSSL_LIBRARIES})

target_link_libraries(sender_cli_ddh PUBLIC oc::libOTe)

target_link_libraries(sender_cli_ddh PUBLIC OpenMP::OpenMP_CXX)

##### target cli for receiver #########

target_link_libraries(receiver_cli_osn
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
TARGET_LINK_LIBRARIES(receiver_cli_osn PUBLIC ${OPENSSL_LIBRARIES})
target_link_libraries(receiver_cli_osn PUBLIC oc::libOTe)

target_link_libraries(receiver_cli_osn PUBLIC OpenMP::OpenMP_CXX)



target_link_libraries(receiver_cli_ddh
    PUBLIC SEAL::seal
    PUBLIC Kuku::kuku
    PUBLIC flatbuffers::flatbuffers
    PUBLIC jsoncpp_static)
target_link_libraries(receiver_cli_ddh PUBLIC ${OPENSSL_LIBRARIES})

target_link_libraries(receiver_cli_ddh PUBLIC oc::libOTe)


target_link_libraries(receiver_cli_ddh PUBLIC OpenMP::OpenMP_CXX)
##### target link option for sender #########


target_link_options(sender_cli_osn PUBLIC -fPIC -no-pie)
target_compile_options(sender_cli_osn PUBLIC -fPIC -no-pie)
if(APSU_USE_LOG4CPLUS)
    target_link_libraries(sender_cli_osn PUBLIC log4cplus::log4cplus)
endif()
if(APSU_USE_ZMQ)
    target_link_libraries(sender_cli_osn PRIVATE libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(sender_cli_osn PUBLIC -DHAVE_CONFIG)
target_compile_options(sender_cli_osn PUBLIC -DUSE_SECURE_SEED)
target_compile_options(sender_cli_osn PUBLIC -DUSE_ENDO=true)


target_link_options(sender_cli_ddh PUBLIC -fPIC -no-pie)
target_compile_options(sender_cli_ddh PUBLIC -fPIC -no-pie)
if(APSU_USE_LOG4CPLUS)
    target_link_libraries(sender_cli_ddh PUBLIC log4cplus::log4cplus)
endif()
if(APSU_USE_ZMQ)
    target_link_libraries(sender_cli_ddh PRIVATE libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(sender_cli_ddh PUBLIC -DHAVE_CONFIG)
target_compile_options(sender_cli_ddh PUBLIC -DUSE_SECURE_SEED)
target_compile_options(sender_cli_ddh PUBLIC -DUSE_ENDO=true)
##### target link option for sender #########


target_link_options(receiver_cli_ddh PUBLIC -fPIC -no-pie)
target_compile_options(receiver_cli_ddh PUBLIC -fPIC -no-pie)
if(APSU_USE_LOG4CPLUS)
    target_link_libraries(receiver_cli_ddh PUBLIC log4cplus::log4cplus)
endif()
if(APSU_USE_ZMQ)
    target_link_libraries(receiver_cli_ddh PRIVATE libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(receiver_cli_ddh PUBLIC -DHAVE_CONFIG)
target_compile_options(receiver_cli_ddh PUBLIC -DUSE_SECURE_SEED)
target_compile_options(receiver_cli_ddh PUBLIC -DUSE_ENDO=true)   


target_link_options(receiver_cli_osn PUBLIC -fPIC -no-pie)
target_compile_options(receiver_cli_osn PUBLIC -fPIC -no-pie)
if(APSU_USE_LOG4CPLUS)
    target_link_libraries(receiver_cli_osn PUBLIC log4cplus::log4cplus)
endif()
if(APSU_USE_ZMQ)
    target_link_libraries(receiver_cli_osn PRIVATE libzmq-static cppzmq-static)
endif()

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(receiver_cli_osn PUBLIC -DHAVE_CONFIG)
target_compile_options(receiver_cli_osn PUBLIC -DUSE_SECURE_SEED)
target_compile_options(receiver_cli_osn PUBLIC -DUSE_ENDO=true)   

####### Set system for sender ######
if(MSVC)
    target_compile_options(sender_cli_osn PUBLIC -D__WINDOWS__)
    target_compile_options(receiver_cli_osn PUBLIC -D__WINDOWS__)
    target_compile_options(sender_cli_ddh PUBLIC -D__WINDOWS__)
    target_compile_options(receiver_cli_ddh PUBLIC -D__WINDOWS__)
elseif (UNIX)
    target_compile_options(sender_cli_osn PUBLIC -D__LINUX__)
    target_compile_options(receiver_cli_osn PUBLIC -D__LINUX__)
    target_compile_options(sender_cli_ddh PUBLIC -D__LINUX__)
    target_compile_options(receiver_cli_ddh PUBLIC -D__LINUX__)
endif()

####### Set architecture  #######
include(DetectArch)
if(APSU_FOURQ_AMD64)
    target_compile_options(sender_cli_osn PUBLIC -D_AMD64_)
    target_compile_options(receiver_cli_osn PUBLIC -D_AMD64_)
    target_compile_options(sender_cli_ddh PUBLIC -D_AMD64_)
    target_compile_options(receiver_cli_ddh PUBLIC -D_AMD64_)
    message(STATUS "FourQlib optimization: arch=AMD64")
elseif (APSU_FOURQ_ARM64)
    target_compile_options(sender_cli_osn PUBLIC -D_ARM64_)
    target_compile_options(sender_cli_ddh PUBLIC -D_ARM64_)
    target_compile_options(receiver_cli_osn PUBLIC -D_ARM64_)
    target_compile_options(receiver_cli_ddh PUBLIC -D_ARM64_)
    message(STATUS "FourQlib optimization: arch=ARM64")
else()
    target_compile_options(sender_cli_osn PUBLIC -D_GENERIC_)
    target_compile_options(sender_cli_ddh PUBLIC -D_GENERIC_)
    target_compile_options(receiver_cli_osn PUBLIC -D_GENERIC_)
    target_compile_options(receiver_cli_ddh PUBLIC -D_GENERIC_)
    message(STATUS "FourQlib optimization: arch=GENERIC")
endif()
if(NOT MSVC)
    target_compile_options(sender_cli_osn PUBLIC -march=native)
    target_compile_options(sender_cli_ddh PUBLIC -march=native)
    target_compile_options(receiver_cli_osn PUBLIC -march=native)
    target_compile_options(receiver_cli_ddh PUBLIC -march=native)
endif()

####### Set AVX or AVX2 if not generic #######
if(APSU_FOURQ_AMD64 OR APSU_FOURQ_ARM64)
    include(FindAVX)
    check_for_avx(sender_cli_osn)

    if (HAVE_AVX2_EXTENSIONS)
        target_compile_options(sender_cli_osn PUBLIC -D_AVX2_)
        target_compile_options(sender_cli_ddh PUBLIC -D_AVX2_)
        target_compile_options(receiver_cli_osn PUBLIC -D_AVX2_)
        target_compile_options(receiver_cli_ddh PUBLIC -D_AVX2_)
        message(STATUS "FourQlib optimization: simd=AVX2")
    elseif(HAVE_AVX_EXTENSIONS)
        target_compile_options(sender_cli_osn PUBLIC -D_AVX_)
        target_compile_options(sender_cli_ddh PUBLIC -D_AVX_)
        target_compile_options(receiver_cli_osn PUBLIC -D_AVX_)
        target_compile_options(receiver_cli_ddh PUBLIC -D_AVX_)
        message(STATUS "FourQlib optimization: simd=AVX")
    endif()
    else()
        message(STATUS "FourQlib optimization: simd=OFF")
endif()

####### Use optimized assembly on Linux (non-AVX or AVX2) ######
set(APSU_FOURQ_USE_ASM OFF)
if(UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
check_language(ASM)
    if(CMAKE_ASM_COMPILER)
        enable_language(ASM)
        target_compile_options(sender_cli_osn PUBLIC -D_ASM_)
        target_compile_options(sender_cli_ddh PUBLIC -D_ASM_)
        target_compile_options(receiver_cli_osn PUBLIC -D_ASM_)
        target_compile_options(receiver_cli_ddh PUBLIC -D_ASM_)
        set(APSU_FOURQ_USE_ASM ON)
        message(STATUS "FourQlib optimization: asm=ON")
    endif()
endif()
# Add source files to library and header files to install
# Must follow configurations for FourQlib
set(APSU_SOURCE_FILES "")
set(APSU_SOURCE_FILES_SENDER "")
set(APSU_SOURCE_FILES_RECEIVER "")
set(APSU_SOURCE_FILES_SENDER_OSN "")
set(APSU_SOURCE_FILES_SENDER_DDH "")
set(APSU_SOURCE_FILES_RECEIVER_OSN "")
set(APSU_SOURCE_FILES_RECEIVER_DDH "")

add_subdirectory(common/apsu)
add_subdirectory(sender/apsu)
add_subdirectory(receiver/apsu)
message(STATUS ${APSU_SOURCE_FILES_SENDER_DDH})
#message(STATUS "${APSU_SOURCE_FILES_SENDER}")
target_sources(sender_cli_osn   PRIVATE ${APSU_SOURCE_FILES_SENDER}
                                PRIVATE ${APSU_SOURCE_FILES_SENDER_OSN}
)       
target_sources(receiver_cli_osn PRIVATE ${APSU_SOURCE_FILES_RECEIVER}
                                PRIVATE ${APSU_SOURCE_FILES_RECEIVER_OSN}
)
target_sources(sender_cli_ddh   PRIVATE ${APSU_SOURCE_FILES_SENDER}
                                PRIVATE ${APSU_SOURCE_FILES_SENDER_DDH}
)       
target_sources(receiver_cli_ddh PRIVATE ${APSU_SOURCE_FILES_RECEIVER}
                                PRIVATE ${APSU_SOURCE_FILES_RECEIVER_DDH}
)
target_compile_definitions(sender_cli_osn PUBLIC __OSN__)
target_compile_definitions(receiver_cli_osn PUBLIC __OSN__)



target_include_directories(sender_cli_osn PUBLIC cli)
target_include_directories(sender_cli_ddh PUBLIC cli)
target_include_directories(sender_cli_osn PUBLIC ${TCLAP_INCLUDE_DIRS})
target_include_directories(sender_cli_ddh PUBLIC ${TCLAP_INCLUDE_DIRS})
target_include_directories(receiver_cli_osn PUBLIC cli)
target_include_directories(receiver_cli_ddh PUBLIC cli)
target_include_directories(receiver_cli_osn PUBLIC ${TCLAP_INCLUDE_DIRS})
target_include_directories(receiver_cli_ddh PUBLIC ${TCLAP_INCLUDE_DIRS})
add_subdirectory(cli/sender)
add_subdirectory(cli/receiver)
target_sources(sender_cli_osn
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/cli/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cli/csv_reader.cpp
)
target_sources(receiver_cli_osn
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/cli/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cli/csv_reader.cpp
)

target_sources(sender_cli_ddh
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/cli/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cli/csv_reader.cpp
)
target_sources(receiver_cli_ddh
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/cli/common_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cli/csv_reader.cpp
)
