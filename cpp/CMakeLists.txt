cmake_minimum_required(VERSION 3.16)
project(licenserail VERSION 0.1.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(LICENSERAIL_WITH_CURL "Default HTTP transport via libcurl (hosts like JUCE can supply their own)" ON)
option(LICENSERAIL_BUILD_TESTS "Build the test-vector runner" ON)

include(FetchContent)
# mbedTLS (Apache-2.0): ECDSA P-256 verify and SHA-256, small and easy to embed in plugins.
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
# mbedTLS builds its TLS library too; newer compilers warn in it, and those warnings are not ours to fail on.
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(mbedtls GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git GIT_TAG v3.6.2 GIT_SHALLOW TRUE)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(mbedtls json)

add_library(licenserail src/core.cpp src/client.cpp src/c_api.cpp)
target_include_directories(licenserail PUBLIC include)
target_link_libraries(licenserail PUBLIC mbedcrypto PRIVATE nlohmann_json::nlohmann_json)
if(LICENSERAIL_WITH_CURL)
  find_package(CURL REQUIRED)
  target_link_libraries(licenserail PRIVATE CURL::libcurl)
  target_compile_definitions(licenserail PRIVATE LICENSERAIL_WITH_CURL=1)
endif()

if(LICENSERAIL_BUILD_TESTS)
  add_executable(licenserail_vectors tests/vectors.cpp)
  target_link_libraries(licenserail_vectors PRIVATE licenserail nlohmann_json::nlohmann_json)
  enable_testing()
  add_test(NAME vectors COMMAND licenserail_vectors ${CMAKE_CURRENT_SOURCE_DIR}/../test-vectors)
endif()
