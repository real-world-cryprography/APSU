# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter_table.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter.cpp
    ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter_table.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter.h
        ${CMAKE_CURRENT_LIST_DIR}/cuckoo_filter_table.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/util
)

set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
