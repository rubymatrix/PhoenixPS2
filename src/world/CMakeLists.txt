set(SOURCES
    besieged_system.cpp
    besieged_system.h
    campaign_system.cpp
    campaign_system.h
    character_cache.cpp
    character_cache.h
    colonization_system.cpp
    colonization_system.h
    conquest_system.cpp
    conquest_system.h
    daily_tally.h
    daily_tally.cpp
    federation_gateway.cpp
    federation_gateway.h
    http_server.cpp
    http_server.h
    ipc_server.cpp
    ipc_server.h
    party_system.cpp
    party_system.h
    time_server.h
    time_server.cpp
    world_application.cpp
    world_application.h
    world_engine.cpp
    world_engine.h
    zone_settings.h
)

# Federation gateway tokens (ext/xitoken), built against the bundled OpenSSL and json targets.
set(XITOKEN_CRYPTO_TARGET libcrypto)
set(XITOKEN_JSON_TARGET nlohmann_json::nlohmann_json)
add_subdirectory(${CMAKE_SOURCE_DIR}/ext/xitoken ${CMAKE_BINARY_DIR}/ext/xitoken)

xi_add_library(xi_world_lib ${SOURCES})
target_include_directories(xi_world_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# HTTPS for the HTTP server (network.HTTP_TLS). httplib is only used by xi_world, so every file that includes it
# sees the same setting.
target_compile_definitions(xi_world_lib PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(xi_world_lib
    PUBLIC
        xi_data_core
        xi_connect_lib # character name rules and creation (login_helpers), shared with xi_connect
        xitoken
        ${WORLD_ONLY_EXTERNAL_LIBS}
)

xi_add_executable(xi_world worldserver.rc ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_link_libraries(xi_world PRIVATE xi_world_lib)
