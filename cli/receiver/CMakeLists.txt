# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(receiver_cli_osn
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/receiver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/receiver_utils.cpp
)
target_sources(receiver_cli_ddh
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/receiver.cpp
        ${CMAKE_CURRENT_LIST_DIR}/receiver_utils.cpp
)
