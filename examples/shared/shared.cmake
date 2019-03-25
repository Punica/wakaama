# Provides SHARED_SOURCES_DIR, SHARED_SOURCES, SHARED_INCLUDE_DIRS and SHARED_DEFINITIONS variables

set(SHARED_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(SHARED_SOURCES 
    ${SHARED_SOURCES_DIR}/commandline.c
    ${SHARED_SOURCES_DIR}/platform.c
	${SHARED_SOURCES_DIR}/memtrace.c)

if(NOT CUSTOM_CONNECTION_HANDLING)
    if(DTLS)
        include(${CMAKE_CURRENT_LIST_DIR}/tinydtls.cmake)
    
        set(SHARED_SOURCES
            ${SHARED_SOURCES}
            ${TINYDTLS_SOURCES}
            ${SHARED_SOURCES_DIR}/dtlsconnection.c)

        set(SHARED_INCLUDE_DIRS
            ${SHARED_SOURCES_DIR}
            ${TINYDTLS_SOURCES_DIR})

        set(SHARED_DEFINITIONS -DWITH_TINYDTLS)
    else()
        set(SHARED_SOURCES
            ${SHARED_SOURCES}
            ${SHARED_SOURCES_DIR}/connection.c)

        set(SHARED_INCLUDE_DIRS ${SHARED_SOURCES_DIR})
    endif()
endif()


