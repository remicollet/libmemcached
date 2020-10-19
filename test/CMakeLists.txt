if(NOT BUILD_TESTING OR NOT CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    return()
endif()

include(CMake/Catch.cmake)

if(NOT MEMCACHED_BINARY)
    message(SEND_ERROR "Could not find memcached(1) binary")
    set(ENV{INVALID_CONFIGURATION} 1)
endif()


check_decl(pipe2 unistd.h)
check_decl(SOCK_NONBLOCK sys/socket.h)
check_decl(SOCK_CLOEXEC sys/socket.h)

if(ENABLE_MEMASLAP AND LIBEVENT AND HAVE_C_STDATOMIC)
    set(HAVE_MEMASLAP 1)
endif()

file(GLOB_RECURSE TESTING_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.cpp)
set(TESTING_ROOT ${CMAKE_CURRENT_BINARY_DIR})
set_source_files_properties(main.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
configure_file(conf.h.in conf.h @ONLY)
add_executable(runtests ${TESTING_SRC})
set_target_properties(runtests PROPERTIES CXX_STANDARD 17)
target_include_directories(runtests PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/src)
target_link_libraries(runtests PRIVATE libhashkit libmemcachedinternal libmemcachedutil)
add_dependencies(runtests ${CLIENTS})

catch_discover_tests(runtests
        TEST_SPEC "lib*")
catch_discover_tests(runtests
        TEST_SPEC "hashkit*")
catch_discover_tests(runtests
        TEST_SPEC "memcached*")
catch_discover_tests(runtests
        TEST_SPEC "bin/*")