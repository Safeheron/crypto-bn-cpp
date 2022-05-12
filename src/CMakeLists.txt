find_package(PkgConfig REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

target_sources(${CMAKE_PROJECT_NAME} PRIVATE
        crypto-bn/bn.cpp
        crypto-bn/rand.cpp
        )

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME}
        OpenSSL::Crypto
        -ldl
        )
