# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/apsu_benes.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNReceiver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNSender.cpp
)
set(APSU_SOURCE_FILES_SENDER_OSN ${APSU_SOURCE_FILES_SENDER_OSN}
    ${CMAKE_CURRENT_LIST_DIR}/apsu_benes.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNReceiver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNSender.cpp
)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN}
    ${CMAKE_CURRENT_LIST_DIR}/apsu_benes.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNReceiver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNSender.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/apsu_benes.h
        ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNReceiver.h
        ${CMAKE_CURRENT_LIST_DIR}/apsu_OSNSender.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/permute
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER_OSN ${APSU_SOURCE_FILES_SENDER_OSN} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN} PARENT_SCOPE)

