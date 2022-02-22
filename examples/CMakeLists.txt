cmake_minimum_required(VERSION 3.10)
project(test)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")
SET(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Ofast")
#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Ofast")

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL Not Found!")
endif (NOT OpenSSL_FOUND)

find_package(CryptoBN REQUIRED)
if (NOT CryptoBN_FOUND)
    message(FATAL_ERROR "CryptoBN Not Found!")
endif (NOT CryptoBN_FOUND)

include_directories(${CryptoBN_INCLUDE_DIRS}
                    ${OPENSSL_INCLUDE_DIR})

add_executable(bn-test bn-test.cpp)
target_link_libraries( bn-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        pthread )