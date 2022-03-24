find_package(GTest REQUIRED)

add_executable(bn-test bn-test.cpp)
target_include_directories(bn-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-test COMMAND bn-test)

add_executable(rnd-test rnd-test.cpp)
target_include_directories(rnd-test PRIVATE
        "../src"
        ${PROTOBUF_LIBRARY_DIRS})
target_link_libraries(rnd-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME rnd-test COMMAND rnd-test)


