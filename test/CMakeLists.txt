cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(GTest REQUIRED)
if(GTest_FOUND )
    MESSAGE(STATUS "============> Found GTest!")
    message(STATUS "GTEST_INCLUDE_DIRS=${GTEST_INCLUDE_DIRS}")
    message(STATUS "GTEST_BOTH_LIBRARIES=${GTEST_BOTH_LIBRARIES}")
    include_directories(${GTEST_INCLUDE_DIRS})
endif(GTest_FOUND )

include_directories("../src")

add_executable(bn-test bn-test.cpp)
target_link_directories(bn-test PUBLIC ${PROTOBUF_LIBRARY_DIRS})
target_link_libraries( bn-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        pthread )
add_test(NAME test-bn COMMAND bn-test)

add_executable(rnd-test rnd-test.cpp)
target_link_directories(rnd-test PUBLIC ${PROTOBUF_LIBRARY_DIRS})
target_link_libraries( rnd-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        pthread )
add_test(NAME test_rnd COMMAND rnd-test)


