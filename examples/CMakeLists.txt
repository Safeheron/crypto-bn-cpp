cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")
SET(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Ofast")

message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(CryptoBN REQUIRED)
if (NOT CryptoBN_FOUND)
    message(FATAL_ERROR "CryptoBN Not Found!")
endif (NOT CryptoBN_FOUND)
if( CryptoBN_FOUND )
    MESSAGE(STATUS "Found CryptoBN!")
endif( CryptoBN_FOUND )

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL Not Found!")
endif (NOT OpenSSL_FOUND)

message(STATUS "CryptoBN_INCLUDE_DIRS = ${CryptoBN_INCLUDE_DIRS}")
message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
message(STATUS "CryptoBN_INCLUDES = ${CryptoBN_INCLUDES}")
message(STATUS "CryptoBN_LIBRARY = ${CryptoBN_LIBRARY}")

add_executable(bn-test bn-test.cpp)
target_include_directories(bn-test PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

target_link_libraries( bn-test PUBLIC
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        pthread )