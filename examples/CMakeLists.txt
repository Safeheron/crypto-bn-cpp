cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(GTest REQUIRED)
if(GTest_FOUND )
    MESSAGE(STATUS "Found GTest!")
    message(STATUS "GTEST_INCLUDE_DIRS = ${GTEST_INCLUDE_DIRS}")
endif(GTest_FOUND )

find_package(CryptoBN REQUIRED)
if(CryptoBN_FOUND )
    MESSAGE(STATUS "Found CryptoBN!")
    message(STATUS "CryptoBN_DIR = ${CryptoBN_DIR}")
    message(STATUS "CryptoBN_INCLUDE_DIRS = ${CryptoBN_INCLUDE_DIRS}")
    message(STATUS "CryptoBN_LIBRARY_DIR = ${CryptoBN_LIBRARY_DIR}")
endif(CryptoBN_FOUND )

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    MESSAGE(STATUS "Found OpenSSL!")
    message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
endif (OpenSSL_FOUND)


add_executable(bn-test bn-test.cpp)
target_include_directories(bn-test PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${GTEST_INCLUDE_DIRS}
        )

target_link_libraries( bn-test PUBLIC
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        pthread )