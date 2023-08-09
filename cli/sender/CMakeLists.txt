# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

target_sources(sender_cli_osn
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
)
target_sources(sender_cli_ddh
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/sender.cpp
)
