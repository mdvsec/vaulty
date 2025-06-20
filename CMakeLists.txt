cmake_minimum_required(VERSION 3.12)

if (NOT UNIX)
    message(FATAL_ERROR "This project only supports Linux aarch64 platform.\n")
endif()

project(vaulty CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")
add_executable(vaulty ${SOURCES})
target_include_directories(vaulty PRIVATE ${PROJECT_SOURCE_DIR}/include)

find_package(OpenSSL REQUIRED)
target_include_directories(vaulty PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(vaulty PRIVATE OpenSSL::Crypto)
