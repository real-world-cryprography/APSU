set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/kunlun_ot.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.cpp
)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER}
    ${CMAKE_CURRENT_LIST_DIR}/kunlun_ot.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.cpp
)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER}
    ${CMAKE_CURRENT_LIST_DIR}/kunlun_ot.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.cpp
    # ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.cpp
)

# Add header files for installation
install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/kunlun_ot.h
        # ${CMAKE_CURRENT_LIST_DIR}/oprf_common.h
        # ${CMAKE_CURRENT_LIST_DIR}/oprf_sender.h
        # ${CMAKE_CURRENT_LIST_DIR}/oprf_receiver.h
    DESTINATION
        ${APSU_INCLUDES_INSTALL_DIR}/apsu/ot
)

set(APSU_SOURCE_FILES ${APSU_SOURCE_FILES} PARENT_SCOPE)
set(APSU_SOURCE_FILES_SENDER ${APSU_SOURCE_FILES_SENDER} PARENT_SCOPE)
set(APSU_SOURCE_FILES_RECEIVER ${APSU_SOURCE_FILES_RECEIVER} PARENT_SCOPE)