# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.cpp
    ${CMAKE_CURRENT_LIST_DIR}/query.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_osn.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_db.cpp
)

set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.cpp
    ${CMAKE_CURRENT_LIST_DIR}/query.cpp
    ${CMAKE_CURRENT_LIST_DIR}/receiver_db.cpp
)


set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN} 
    ${CMAKE_CURRENT_LIST_DIR}/receiver_osn.cpp
)

set(APSU_SOURCE_FILES_RECEIVER_DDH ${APSU_SOURCE_FILES_RECEIVER_DDH} 
    ${CMAKE_CURRENT_LIST_DIR}/receiver_ddh.cpp
)
# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/bin_bundle.h
        ${CMAKE_CURRENT_LIST_DIR}/query.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_osn.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_ddh.h
        ${CMAKE_CURRENT_LIST_DIR}/receiver_db.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu
)

add_subdirectory(util)

if(APSU_USE_ZMQ)
    add_subdirectory(zmq)
endif()
set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_OSN ${APSU_SOURCE_FILES_RECEIVER_OSN} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER_DDH ${APSU_SOURCE_FILES_RECEIVER_DDH} PARENT_SCOPE)



