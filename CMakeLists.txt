cmake_minimum_required(VERSION 3.12)

if (NOT UNIX)
    message(FATAL_ERROR "This project only supports UNIX platforms\n")
endif()

project(vaulty CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")
add_executable(vaulty ${SOURCES})
target_include_directories(vaulty PRIVATE ${PROJECT_SOURCE_DIR}/include)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_include_directories(vaulty PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(vaulty PRIVATE OpenSSL::Crypto)

# CLI11
include(FetchContent)
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.5.0
)
FetchContent_MakeAvailable(CLI11)
target_link_libraries(vaulty PRIVATE CLI11::CLI11)
