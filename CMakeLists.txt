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

# Set default build type to Release if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type (Debug, Release)" FORCE)
endif()

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_definitions(DEBUG_MODE)
    target_compile_options(vaulty PRIVATE -Wall -Wextra -pedantic -g -O0)
else()
    target_compile_options(vaulty PRIVATE -Wall -Wextra -pedantic -O3)
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)
target_include_directories(vaulty PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(vaulty PRIVATE OpenSSL::Crypto)

# SQLite3
find_package(SQLite3 REQUIRED)
target_link_libraries(vaulty PRIVATE SQLite::SQLite3)

# CLI11
include(FetchContent)
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.5.0
)
FetchContent_MakeAvailable(CLI11)
target_link_libraries(vaulty PRIVATE CLI11::CLI11)

# clip
set(CLIP_EXAMPLES OFF CACHE BOOL "Compile clip examples")
set(CLIP_TESTS OFF CACHE BOOL "Compile clip tests")
FetchContent_Declare(
  clip
  GIT_REPOSITORY https://github.com/dacap/clip.git
  GIT_TAG main
)
FetchContent_MakeAvailable(clip)
target_include_directories(vaulty PRIVATE ${clip_SOURCE_DIR})
target_link_libraries(vaulty PRIVATE clip)
