# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
if(APSU_FOURQ_USE_ASM)
    if(HAVE_AVX2_EXTENSIONS)
        set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
            ${CMAKE_CURRENT_LIST_DIR}/consts.c
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271_AVX2.S
        )
        set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
            ${CMAKE_CURRENT_LIST_DIR}/consts.c
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271_AVX2.S
        )
        set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
            ${CMAKE_CURRENT_LIST_DIR}/consts.c
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271_AVX2.S
        )
    else()
        set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271.S
        )
        set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271.S
        )
        set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
            ${CMAKE_CURRENT_LIST_DIR}/fp2_1271.S
        )
    endif()
endif()

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/fp_x64.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/fourq/amd64
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)

set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)

