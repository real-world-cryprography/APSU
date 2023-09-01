# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/item.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/powers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/psu_params.cpp
    ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.cpp
    ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
    ${CMAKE_CURRENT_LIST_DIR}/item.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/powers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/psu_params.cpp
    ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.cpp
    ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/item.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log.cpp
    ${CMAKE_CURRENT_LIST_DIR}/powers.cpp
    ${CMAKE_CURRENT_LIST_DIR}/psu_params.cpp
    ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.cpp
    ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/apsu.h
        ${CMAKE_CURRENT_LIST_DIR}/crypto_context.h
        ${CMAKE_CURRENT_LIST_DIR}/item.h
        ${CMAKE_CURRENT_LIST_DIR}/log.h
        ${CMAKE_CURRENT_LIST_DIR}/powers.h
        ${CMAKE_CURRENT_LIST_DIR}/psu_params.h
        ${CMAKE_CURRENT_LIST_DIR}/requests.h
        ${CMAKE_CURRENT_LIST_DIR}/responses.h
        ${CMAKE_CURRENT_LIST_DIR}/seal_object.h
        ${CMAKE_CURRENT_LIST_DIR}/thread_pool_mgr.h
        ${CMAKE_CURRENT_LIST_DIR}/version.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu
)

add_subdirectory(fourq)
add_subdirectory(network)
add_subdirectory(oprf)
add_subdirectory(util)
add_subdirectory(permute)
add_subdirectory(peqt)
add_subdirectory(ot)
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER_OSN ${APSU_SOURCE_FILES_SENDER_OSN} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER_DDH ${APSU_SOURCE_FILES_SENDER_DDH} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_DDH ${APSU_SOURCE_FILES_RECEIVER_DDH} PARENT_SCOPE)
