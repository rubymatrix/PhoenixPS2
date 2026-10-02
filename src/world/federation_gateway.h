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
#include <memory>
#include <mutex>
#include <string>

class IPCServer;
class Scheduler;

// Federation gateway: PlayOnline providers (e.g. Project Crystal) admit players to this world with signed,
// single-use xi.world-entry/1 tokens (ext/xitoken/SPEC.md) instead of writing accounts_sessions themselves.
// Served by xi_world's HTTP server at POST /xi/v1/world-entry.
class FederationGateway
{
public:
    // Reads the network.FEDERATION_* settings. Returns nullptr, after logging why, when the gateway is off or
    // misconfigured.
    static auto create(Scheduler& scheduler, IPCServer& ipcServer) -> std::unique_ptr<FederationGateway>;

    // Called from the HTTP server's thread before it starts listening.
    void registerRoutes(httplib::Server& server);

private:
    FederationGateway(Scheduler& scheduler, IPCServer& ipcServer, std::string serverId, std::string trustDir);

    // Replay guard shared by every process that reads the world database.
    class DbReplayGuard : public xitoken::ReplayGuard
    {
    public:
        auto tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool override;
    };

    auto worldEntry(const std::string& token, const std::string& peer) -> std::pair<int, nlohmann::json>;
    void reloadTrust(bool force);

    Scheduler&  scheduler_;
    IPCServer&  ipcServer_;
    std::string serverId_;
    std::string trustDir_;

    xitoken::KeySetResolver keys_;
    DbReplayGuard           replay_;
    xitoken::Verifier       verifier_;

    std::mutex                            reloadMutex_;
    std::chrono::steady_clock::time_point lastReload_{};
};
