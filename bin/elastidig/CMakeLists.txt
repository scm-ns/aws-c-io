project(elastidig C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/cmake")

file(GLOB ELASTIDIG_SRC
        "*.c"
        )

set(ELASTIDIG_PROJECT_NAME elastidig)
add_executable(${ELASTIDIG_PROJECT_NAME} ${ELASTIDIG_SRC})
aws_set_common_properties(${ELASTIDIG_PROJECT_NAME})


target_include_directories(${ELASTIDIG_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${ELASTIDIG_PROJECT_NAME} aws-c-io)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " elastidig will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${ELASTIDIG_PROJECT_NAME}
        EXPORT ${ELASTIDIG_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
