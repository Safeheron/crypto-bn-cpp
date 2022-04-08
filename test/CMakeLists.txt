find_package(GTest REQUIRED)

add_executable(bn-arithmetic-operation-test bn-arithmetic-operation-test.cpp)
target_include_directories(bn-arithmetic-operation-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-arithmetic-operation-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-arithmetic-operation-test COMMAND bn-arithmetic-operation-test)

add_executable(bn-assignment-test bn-assignment-test.cpp)
target_include_directories(bn-assignment-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-assignment-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-assignment-test COMMAND bn-assignment-test)

add_executable(bn-auxiliary-test bn-auxiliary-test.cpp)
target_include_directories(bn-auxiliary-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-auxiliary-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-auxiliary-test COMMAND bn-auxiliary-test)

add_executable(bn-bit-operation-test bn-bit-operation-test.cpp)
target_include_directories(bn-bit-operation-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-bit-operation-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-bit-operation-test COMMAND bn-bit-operation-test)

add_executable(bn-bytes-conversion-test bn-bytes-conversion-test.cpp)
target_include_directories(bn-bytes-conversion-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-bytes-conversion-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-bytes-conversion-test COMMAND bn-bytes-conversion-test)

add_executable(bn-comparison-test bn-comparison-test.cpp)
target_include_directories(bn-comparison-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-comparison-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-comparison-test COMMAND bn-comparison-test)

add_executable(bn-constructor-test bn-constructor-test.cpp)
target_include_directories(bn-constructor-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-constructor-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-constructor-test COMMAND bn-constructor-test)

add_executable(bn-number-theory-func-test bn-number-theory-func-test.cpp)
target_include_directories(bn-number-theory-func-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-number-theory-func-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-number-theory-func-test COMMAND bn-number-theory-func-test)

add_executable(bn-string-conversion-test bn-string-conversion-test.cpp)
target_include_directories(bn-string-conversion-test PRIVATE
        "../src"
        ${GTEST_INCLUDE_DIRS})
target_link_libraries(bn-string-conversion-test
        CryptoBN
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LIBRARY_DIRS}
        pthread )
add_test(NAME bn-string-conversion-test COMMAND bn-string-conversion-test)

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


