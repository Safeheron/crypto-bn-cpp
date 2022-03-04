cmake_minimum_required(VERSION 3.10)
project(CryptoBN)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

find_package(PkgConfig REQUIRED)
if(PkgConfig_FOUND )
    MESSAGE(STATUS "============> Found PkgConfig!")
endif(PkgConfig_FOUND )

pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file
if(PROTOBUF_FOUND )
    message(STATUS "============> Found PROTOBUF!")
endif(PROTOBUF_FOUND )

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    message(STATUS "============> Found OpenSSL!")
endif (OpenSSL_FOUND)


add_library(${PROJECT_NAME} SHARED
        crypto-bn/bn.cpp
        crypto-bn/rand.cpp
        )

target_include_directories(${PROJECT_NAME} PUBLIC
        ${PROTOBUF_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${PROJECT_NAME}
        ${PROTOBUF_LINK_LIBRARIES}
        OpenSSL::Crypto
        -ldl
        )
