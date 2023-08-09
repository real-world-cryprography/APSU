# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/fourq/generic
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
