cmake_minimum_required(VERSION 3.12)

if (NOT UNIX)
    message(FATAL_ERROR "This project only supports UNIX platforms\n")
endif()

project(vaulty CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set default build type to Release if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Debug, Release)" FORCE)
endif()

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_definitions(DEBUG_MODE)
    set(COMMON_COMPILE_OPTIONS -Wall -Wextra -pedantic -g -O0)
else()
    set(COMMON_COMPILE_OPTIONS -Wall -Wextra -pedantic -O3)
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)

# SQLite3
find_package(SQLite3 REQUIRED)

# CLI11
include(FetchContent)
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.5.0
)
FetchContent_MakeAvailable(CLI11)

# clip
set(CLIP_EXAMPLES OFF CACHE BOOL "Compile clip examples")
set(CLIP_TESTS OFF CACHE BOOL "Compile clip tests")
FetchContent_Declare(
    clip
    GIT_REPOSITORY https://github.com/dacap/clip.git
    GIT_TAG main
)
FetchContent_MakeAvailable(clip)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.15.3
)
FetchContent_MakeAvailable(spdlog)

# Core
file(GLOB CORE_SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")
add_library(vaulty_core ${CORE_SOURCES})

target_include_directories(vaulty_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${clip_SOURCE_DIR}
)
target_link_libraries(vaulty_core PUBLIC
    OpenSSL::Crypto
    SQLite::SQLite3
    CLI11::CLI11
    clip
    spdlog::spdlog
)
target_compile_options(vaulty_core PRIVATE ${COMMON_COMPILE_OPTIONS})

# Main executable
add_executable(vaulty src/main.cpp)
target_link_libraries(vaulty PRIVATE vaulty_core)

# GoogleTest
enable_testing()

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG main
)
FetchContent_MakeAvailable(googletest)

file(GLOB TEST_SOURCES "${PROJECT_SOURCE_DIR}/tests/*.cpp")
if (TEST_SOURCES)
    list(REMOVE_ITEM CORE_SOURCES "${PROJECT_SOURCE_DIR}/src/main.cpp")

    add_executable(vaulty_tests ${TEST_SOURCES} ${CORE_SOURCES})

    target_compile_definitions(vaulty_tests PRIVATE UNIT_TESTING)
    target_compile_options(vaulty_tests PRIVATE ${COMMON_COMPILE_OPTIONS})
    target_link_libraries(vaulty_tests PRIVATE
        GTest::gtest_main
        vaulty_core
    )

    include(GoogleTest)
    gtest_discover_tests(vaulty_tests)
endif()
