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

#include "federation_gateway.h"

#include "ipc_server.h"

#include "common/database.h"
#include "common/ipc_structs.h"
#include "common/logging.h"
#include "common/scheduler.h"
#include "common/settings.h"

#include <filesystem>

using json = nlohmann::json;

namespace
{
    constexpr uint8 ACCOUNT_STATUS_NORMAL = 0x01; // ACCOUNT_STATUS_CODE::NORMAL in login/auth_session.h

    auto reply(int status, std::string_view error) -> std::pair<int, json>
    {
        return { status, json{ { "ok", false }, { "error", error } } };
    }
} // namespace

auto FederationGateway::create(Scheduler& scheduler, IPCServer& ipcServer) -> std::unique_ptr<FederationGateway>
{
    if (!settings::get<bool>("network.ENABLE_FEDERATION_GATEWAY"))
    {
        return nullptr;
    }

    auto serverId = settings::get<std::string>("network.FEDERATION_SERVER_ID");
    auto trustDir = settings::get<std::string>("network.FEDERATION_TRUST_DIR");
    if (!xitoken::isValidServerId(serverId))
    {
        ShowErrorFmt("Federation gateway disabled: network.FEDERATION_SERVER_ID '{}' is not a server id (xitoken-cli keygen prints one)", serverId);
        return nullptr;
    }

    auto gateway = std::unique_ptr<FederationGateway>(new FederationGateway(scheduler, ipcServer, serverId, trustDir));
    gateway->reloadTrust(true);
    ShowInfoFmt("Federation gateway: world {} trusts {} provider(s) from {}", serverId, gateway->keys_.size(), trustDir);
    return gateway;
}

FederationGateway::FederationGateway(Scheduler& scheduler, IPCServer& ipcServer, std::string serverId, std::string trustDir)
: scheduler_(scheduler)
, ipcServer_(ipcServer)
, serverId_(std::move(serverId))
, trustDir_(std::move(trustDir))
, verifier_(keys_, xitoken::VerifierOptions{ .audience = serverId_, .replayGuard = &replay_ })
{
}

void FederationGateway::registerRoutes(httplib::Server& server)
{
    server.Post(
        "/xi/v1/world-entry",
        [this](const httplib::Request& req, httplib::Response& res)
        {
            auto [status, body] = worldEntry(req.body, req.remote_addr);
            res.status          = status;
            res.set_content(body.dump(), "application/json");
        });
}

// Trust is a file per provider in the trust directory, named <server id>.keyset. Key sets are re-read at most once
// a minute, so a provider's rotation or a newly added provider is picked up without a restart.
void FederationGateway::reloadTrust(bool force)
{
    std::lock_guard<std::mutex> lock(reloadMutex_);
    auto                        now = std::chrono::steady_clock::now();
    if (!force && now - lastReload_ < std::chrono::minutes(1))
    {
        return;
    }
    lastReload_ = now;

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(trustDir_, ec))
    {
        const auto& path = entry.path();
        if (!entry.is_regular_file() || path.extension() != ".keyset")
        {
            continue;
        }
        std::string providerId = path.stem().string();
        std::string error;
        // Re-reading an unchanged file succeeds (it is not older than itself), so only real problems are logged.
        if (!keys_.trustFile(path.string(), providerId, -1, &error))
        {
            ShowWarningFmt("Federation gateway: not trusting {}: {}", path.string(), error);
        }
    }
    if (ec)
    {
        ShowWarningFmt("Federation gateway: cannot read trust directory {}: {}", trustDir_, ec.message());
    }
}

auto FederationGateway::worldEntry(const std::string& token, const std::string& peer) -> std::pair<int, json>
{
    reloadTrust(false);

    auto result = verifier_.verify(token, xitoken::WorldEntry::type);
    if (!result)
    {
        ShowWarningFmt("Federation gateway: rejected world-entry from {}: {}", peer, xitoken::toString(result.error));
        return reply(400, xitoken::toString(result.error));
    }
    auto entry = xitoken::WorldEntry::fromClaims(result.token->claims);
    if (!entry)
    {
        return reply(400, "bad_entry");
    }
    const auto& provider = result.token->issuer;
    const auto& subject  = result.token->subject;

    // The player's account on this world.
    uint32 accid = 0;
    {
        const auto rset = db::preparedStmt("SELECT f.accid, a.status FROM accounts_federated f JOIN accounts a ON a.id = f.accid "
                                           "WHERE f.provider = ? AND f.subject = ? LIMIT 1",
                                           provider,
                                           subject);
        if (!rset || !rset->next())
        {
            ShowWarningFmt("Federation gateway: {} has no account on this world", result.token->playerId());
            return reply(409, "not_permitted");
        }
        accid = rset->get<uint32>("accid");
        if (!(rset->get<uint8>("status") & ACCOUNT_STATUS_NORMAL))
        {
            return reply(409, "not_permitted");
        }
    }

    // The character, which must belong to that account, and the map server for its zone.
    std::string zoneIp;
    uint16      zonePort = 0;
    uint16      zoneId   = 0;
    uint16      prevZone = 0;
    uint16      gmlevel  = 0;
    {
        const auto rset = db::preparedStmt("SELECT zoneip, zoneport, zoneid, pos_prevzone, gmlevel, accid "
                                           "FROM zone_settings, chars "
                                           "WHERE IF(pos_zone = 0, zoneid = pos_prevzone, zoneid = pos_zone) AND charid = ? LIMIT 1",
                                           entry->charId);
        if (!rset || !rset->next())
        {
            return reply(409, "unknown_character");
        }
        if (rset->get<uint32>("accid") != accid)
        {
            ShowWarningFmt("Federation gateway: {} asked for charid {}, which is not theirs", result.token->playerId(), entry->charId);
            return reply(409, "not_permitted");
        }
        zoneIp   = rset->get<std::string>("zoneip");
        zonePort = rset->get<uint16>("zoneport");
        zoneId   = rset->get<uint16>("zoneid");
        prevZone = rset->get<uint16>("pos_prevzone");
        gmlevel  = rset->get<uint16>("gmlevel");
    }
    if (zoneIp.empty() || zonePort == 0)
    {
        ShowWarningFmt("Federation gateway: no map address for charid {} (zone {}); check zone_settings", entry->charId, zoneId);
        return reply(503, "unavailable");
    }
    if (settings::get<bool>("login.MAINT_MODE") && gmlevel == 0)
    {
        return reply(503, "unavailable");
    }

    // Same session rules as xi_connect's data_session: clear a zone-out that never arrived, one session per account,
    // LOGIN_LIMIT per client address.
    const uint32 clientAddr = entry->clientAddrLsb();
    db::preparedStmt("DELETE FROM accounts_sessions "
                     "WHERE accid = ? AND charid = ? AND client_port = '0' AND last_zoneout_time <= SUBTIME(NOW(), \"00:02:00\")",
                     accid,
                     entry->charId);
    {
        const auto rset = db::preparedStmt("SELECT charid FROM accounts_sessions WHERE accid = ? LIMIT 1", accid);
        if (rset && rset->next())
        {
            return reply(409, "already_logged_in");
        }
    }
    if (const auto loginLimit = settings::get<uint8>("login.LOGIN_LIMIT"); loginLimit > 0 && gmlevel == 0)
    {
        const auto rset = db::preparedStmt("SELECT COUNT(*) AS `count` FROM accounts_sessions WHERE client_addr = ?", clientAddr);
        if (rset && rset->next() && rset->get<uint32>("count") >= loginLimit)
        {
            return reply(409, "login_limit");
        }
    }

    if (prevZone == 0)
    {
        db::preparedStmt("UPDATE chars SET pos_prevzone = ? WHERE charid = ?", zoneId, entry->charId);
    }

    uint8 sessionKey[20] = {};
    std::memcpy(sessionKey, entry->sessionKey.data(), sizeof(sessionKey));
    const bool inserted = static_cast<bool>(db::preparedStmt("INSERT INTO accounts_sessions(accid, charid, session_key, server_addr, server_port, "
                                                             "client_addr, version_mismatch, client_version, client_expansions) "
                                                             "VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?)",
                                                             accid,
                                                             entry->charId,
                                                             sessionKey,
                                                             str2ip(zoneIp),
                                                             zonePort,
                                                             clientAddr,
                                                             entry->clientVersion,
                                                             entry->clientExpansions));
    std::memset(sessionKey, 0, sizeof(sessionKey));
    if (!inserted)
    {
        // accounts_sessions.accid is unique, so a concurrent entry for the same account lands here.
        return reply(409, "already_logged_in");
    }

    db::preparedStmt("UPDATE char_flags SET disconnecting = 0 WHERE charid = ?", entry->charId);
    db::preparedStmt("UPDATE char_stats SET zoning = 2 WHERE charid = ?", entry->charId);

    // Tell the map server the character is on its way, as xi_connect does after a lobby select.
    scheduler_.postToMainThread(
        [&ipcServer = ipcServer_, charId = entry->charId, zoneId]()
        {
            ipcServer.handleMessage_CharZone(IPP{}, ipc::CharZone{
                                                        .charId            = charId,
                                                        .destinationZoneId = static_cast<xi::ZoneId>(zoneId),
                                                    });
        });

    ShowInfoFmt("Federation gateway: admitted charid {} for {} ({} {}) via {}",
                entry->charId,
                result.token->playerId(),
                entry->clientIp,
                entry->clientVersion,
                peer);

    return { 200, json{ { "ok", true }, { "map", { { "ip", zoneIp }, { "port", zonePort } } } } };
}

auto FederationGateway::DbReplayGuard::tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool
{
    if (jti.size() > 64)
    {
        return false;
    }
    db::preparedStmt("DELETE FROM federation_used_tokens WHERE expires < NOW()");
    const auto rset = db::preparedStmt("INSERT IGNORE INTO federation_used_tokens(issuer, jti, expires) VALUES(?, ?, FROM_UNIXTIME(?))",
                                       issuer,
                                       jti,
                                       static_cast<uint32>(keepUntil)); // the binder has no 64-bit integers
    return rset && rset->rowsAffected() == 1;
}
