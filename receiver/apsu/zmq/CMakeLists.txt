# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher_osn.cpp
)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN}
    ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher_osn.cpp
)
set(APSU_SOURCE_FILES_RECEIVER_DDH ${APSU_SOURCE_FILES_RECEIVER_DDH}
    ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher_ddh.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher_osn.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_dispatcher_ddh.h

    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/zmq
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_DDH ${APSU_SOURCE_FILES_RECEIVER_DDH} PARENT_SCOPE)

