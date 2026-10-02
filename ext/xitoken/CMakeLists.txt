cmake_minimum_required(VERSION 3.20)
project(xitoken VERSION 1.0.0 LANGUAGES CXX)

# Embedding: add_subdirectory() this folder and link `xitoken`. If the parent project already has OpenSSL or
# nlohmann/json under other target names, set XITOKEN_CRYPTO_TARGET / XITOKEN_JSON_TARGET before adding it.

add_library(xitoken STATIC src/xitoken.cpp)
add_library(xitoken::xitoken ALIAS xitoken)
target_include_directories(xitoken PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(xitoken PUBLIC cxx_std_17)

if(NOT XITOKEN_CRYPTO_TARGET)
    find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
    set(XITOKEN_CRYPTO_TARGET OpenSSL::Crypto)
endif()

if(NOT XITOKEN_JSON_TARGET)
    if(NOT TARGET nlohmann_json::nlohmann_json)
        find_package(nlohmann_json 3.10 QUIET)
        if(NOT nlohmann_json_FOUND)
            include(FetchContent)
            FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
            FetchContent_MakeAvailable(json)
        endif()
    endif()
    set(XITOKEN_JSON_TARGET nlohmann_json::nlohmann_json)
endif()

target_link_libraries(xitoken PUBLIC ${XITOKEN_CRYPTO_TARGET} ${XITOKEN_JSON_TARGET})

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    option(XITOKEN_BUILD_TESTS "Build the xitoken vector tests" ON)
else()
    option(XITOKEN_BUILD_TESTS "Build the xitoken vector tests" OFF)
endif()

if(XITOKEN_BUILD_TESTS)
    enable_testing()
    add_executable(xitoken_tests tests/test_main.cpp)
    target_link_libraries(xitoken_tests PRIVATE xitoken)
    target_compile_definitions(xitoken_tests PRIVATE XITOKEN_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../vectors")
    add_test(NAME xitoken_tests COMMAND xitoken_tests)
endif()
