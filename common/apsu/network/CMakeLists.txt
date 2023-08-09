# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation_response.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation_response.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
    ${CMAKE_CURRENT_LIST_DIR}/result_package.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_operation_response.cpp
    ${CMAKE_CURRENT_LIST_DIR}/stream_channel.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/channel.h
        ${CMAKE_CURRENT_LIST_DIR}/network_channel.h
        ${CMAKE_CURRENT_LIST_DIR}/result_package.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_operation.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_operation_response.h
        ${CMAKE_CURRENT_LIST_DIR}/stream_channel.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/network
)

if(APSU_USE_ZMQ)
    add_subdirectory(zmq)
endif()
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
