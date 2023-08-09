# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
    ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/interpolate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/db_encoding.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stopwatch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/interpolate.h
        ${CMAKE_CURRENT_LIST_DIR}/label_encryptor.h
        ${CMAKE_CURRENT_LIST_DIR}/db_encoding.h
        ${CMAKE_CURRENT_LIST_DIR}/stopwatch.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool.h
        ${CMAKE_CURRENT_LIST_DIR}/utils.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/util
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
