cmake_minimum_required(VERSION 3.10)

project("crypto-bn" LANGUAGES CXX VERSION 1.0.1)

add_subdirectory(src)
add_subdirectory(test)

include("cmake/setup_installation.cmake")