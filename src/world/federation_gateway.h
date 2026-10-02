/*
===========================================================================

  Copyright (c) 2026 LandSandBoat Dev Teams

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see http://www.gnu.org/licenses/

===========================================================================
*/

#pragma once

#include <xitoken/xitoken.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

class IPCServer;
class Scheduler;

// Federation gateway (ext/xitoken/SPEC.md): PlayOnline providers (e.g. Project Crystal) act for their players on this
// world with signed, single-use tokens instead of reading and writing its database. Served by xi_world's HTTP server:
//   GET  /xi/v1/keyset                      this world's signed key set (id, name, gateway, expansions)
//   POST /xi/v1/world-entry                 admit a character (xi.world-entry/1)
//   GET  /xi/v1/characters                  the player's characters (xi.account/1, as are the calls below)
//   POST /xi/v1/characters                  create one
//   DELETE /xi/v1/characters/<id>           delete one
//   POST /xi/v1/characters/<id>/name        rename one the world flagged for renaming
class FederationGateway
{
public:
    // Reads the network.FEDERATION_* settings. Returns nullptr, after logging why, when the gateway is off or
    // misconfigured.
    static auto create(Scheduler& scheduler, IPCServer& ipcServer) -> std::unique_ptr<FederationGateway>;

    // Called from the HTTP server's thread before it starts listening.
    void registerRoutes(httplib::Server& server);

    auto serverId() const -> const std::string&
    {
        return serverId_;
    }

private:
    using Reply = std::pair<int, nlohmann::json>;

    FederationGateway(Scheduler& scheduler, IPCServer& ipcServer, xitoken::SigningKey identity, std::string trustDir, std::string keySet);

    // Replay guard shared by every process that reads the world database.
    class DbReplayGuard : public xitoken::ReplayGuard
    {
    public:
        auto tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool override;
    };

    struct Account
    {
        uint32_t accid  = 0;
        uint8_t  status = 0;
    };

    auto worldEntry(const std::string& token, const std::string& peer) -> Reply;
    auto listCharacters(const xitoken::Token& player) -> Reply;
    auto createCharacter(const xitoken::Token& player, const std::string& body) -> Reply;
    auto deleteCharacter(const xitoken::Token& player, uint32_t charId) -> Reply;
    auto renameCharacter(const xitoken::Token& player, uint32_t charId, const std::string& body) -> Reply;

    // Verifies the request's "Authorization: XiToken <xi.account/1 token>"; on failure fills `rejection`.
    auto authenticate(const httplib::Request& req, Reply& rejection) -> std::optional<xitoken::Token>;
    static auto findAccount(const xitoken::Token& player) -> std::optional<Account>;
    static auto createAccount(const xitoken::Token& player) -> std::optional<Account>;

    // Runs `fn` on the main thread and waits for it: for code that touches the Lua state (name checks).
    auto onMainThread(std::function<Reply()> fn) -> Reply;

    void reloadTrust(bool force);

    Scheduler&          scheduler_;
    IPCServer&          ipcServer_;
    xitoken::SigningKey identity_;
    std::string         serverId_;
    std::string         trustDir_;
    std::string         keySet_;

    xitoken::KeySetResolver keys_;
    DbReplayGuard           replay_;
    xitoken::Verifier       verifier_;

    std::mutex                            reloadMutex_;
    std::chrono::steady_clock::time_point lastReload_{};
};
