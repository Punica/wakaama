cmake_minimum_required (VERSION 2.8)

project (restserver)

option(CODE_COVERAGE "Enable code coverage" OFF)

if(DTLS)
    message(FATAL_ERROR "DTLS option is not supported." )
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../../core/wakaama.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../shared/shared.cmake)

add_definitions(-DLWM2M_SERVER_MODE)
add_definitions(${SHARED_DEFINITIONS} ${WAKAAMA_DEFINITIONS})

include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})

SET(SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/restserver.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-core.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-core-types.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-endpoints.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-resources.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-notifications.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-subscriptions.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-list.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-utils.c
    ${CMAKE_CURRENT_LIST_DIR}/logging.c
    ${CMAKE_CURRENT_LIST_DIR}/settings.c
    )

add_executable(${PROJECT_NAME} ${SOURCES} ${WAKAAMA_SOURCES} ${SHARED_SOURCES})
find_library(ULFIUS_LIB ulfius)
find_library(JANSSON_LIB jansson)
find_library(BASE64_LIB b64)
target_compile_options(restserver PRIVATE "-Wall")
target_link_libraries(restserver "${ULFIUS_LIB}" "${JANSSON_LIB}" "${BASE64_LIB}")

if(CODE_COVERAGE)
    target_compile_options(restserver PRIVATE "-coverage")
    target_link_libraries(restserver "gcov")
endif()

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)

SOURCE_GROUP(wakaama FILES ${WAKAAMA_SOURCES})
