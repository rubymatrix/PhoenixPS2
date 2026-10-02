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
#include "common/xirand.h"

#include "login/login_helpers.h"

#include <openssl/rand.h>

#include <filesystem>
#include <fstream>
#include <future>
#include <sstream>

using json = nlohmann::json;

namespace
{
    constexpr uint8  ACCOUNT_STATUS_NORMAL = 0x01; // ACCOUNT_STATUS_CODE::NORMAL in login/auth_session.h
    constexpr uint32 MAX_CHARID            = 0xFFFF; // PlayOnline content sub ids carry 16 bits of character id

    auto reply(int status, std::string_view error) -> std::pair<int, json>
    {
        return { status, json{ { "ok", false }, { "error", error } } };
    }

    auto ok(json body = json::object()) -> std::pair<int, json>
    {
        body["ok"] = true;
        return { 200, body };
    }

    auto readFile(const std::string& path) -> std::optional<std::string>
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            return std::nullopt;
        }
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    // The expansions this world enables (main.ENABLE_*), as the FFXI lobby's expansion bitmask.
    auto worldExpansions() -> uint32
    {
        static constexpr std::pair<const char*, uint32> bits[] = {
            { "main.ENABLE_ROTZ", 0x0002 },
            { "main.ENABLE_COP", 0x0004 },
            { "main.ENABLE_TOAU", 0x0008 },
            { "main.ENABLE_WOTG", 0x0010 },
            { "main.ENABLE_ACP", 0x0020 },
            { "main.ENABLE_AMK", 0x0040 },
            { "main.ENABLE_ASA", 0x0080 },
            { "main.ENABLE_ABYSSEA", 0x0100 | 0x0200 | 0x0400 },
            { "main.ENABLE_SOA", 0x0800 },
        };
        uint32 mask = 0x0001; // base game
        for (const auto& [key, bit] : bits)
        {
            if (settings::get<bool>(key))
            {
                mask |= bit;
            }
        }
        return mask;
    }

    auto getUInt(const json& body, const char* name, uint32 max) -> std::optional<uint32>
    {
        auto it = body.find(name);
        if (it == body.end() || !it->is_number_unsigned() || it->get<uint64>() > max)
        {
            return std::nullopt;
        }
        return static_cast<uint32>(it->get<uint64>());
    }

    // validateCharacterName's reason for an unavailable name, as the gateway's error name.
    auto nameError(const std::string& reason) -> std::string_view
    {
        return reason == "Name already in use." ? "name_taken" : "name_invalid";
    }
} // namespace

auto FederationGateway::create(Scheduler& scheduler, IPCServer& ipcServer) -> std::unique_ptr<FederationGateway>
{
    if (!settings::get<bool>("network.ENABLE_FEDERATION_GATEWAY"))
    {
        return nullptr;
    }

    const auto keyPath  = settings::get<std::string>("network.FEDERATION_IDENTITY_KEY");
    const auto trustDir = settings::get<std::string>("network.FEDERATION_TRUST_DIR");
    const auto secret   = readFile(keyPath);
    auto       identity = secret ? xitoken::SigningKey::fromPaserk("identity", *secret) : std::nullopt;
    if (!identity)
    {
        // A secret key file holds one k4.secret line; trailing whitespace is allowed.
        auto trimmed = secret ? secret->substr(0, secret->find_last_not_of(" \r\n\t") + 1) : std::string();
        identity     = xitoken::SigningKey::fromPaserk("identity", trimmed);
    }
    if (!identity)
    {
        ShowErrorFmt("Federation gateway disabled: network.FEDERATION_IDENTITY_KEY '{}' is not a k4.secret key file "
                     "(xitoken-cli keygen --out {} makes one)",
                     keyPath,
                     keyPath);
        return nullptr;
    }

    // The world's own signed key set: its id, name, gateway URL and expansions, for providers to check.
    auto name = settings::get<std::string>("network.FEDERATION_NAME");
    if (name.empty())
    {
        name = settings::get<std::string>("main.SERVER_NAME");
    }
    auto publicUrl = settings::get<std::string>("network.FEDERATION_PUBLIC_URL");
    if (publicUrl.empty())
    {
        publicUrl = fmt::format("{}://{}:{}",
                                settings::get<bool>("network.HTTP_TLS") ? "https" : "http",
                                settings::get<std::string>("network.HTTP_HOST"),
                                settings::get<uint16>("network.HTTP_PORT"));
    }
    xitoken::WorldInfo world{ publicUrl, worldExpansions(), std::nullopt };
    if (auto search = settings::get<std::string>("network.FEDERATION_SEARCH_ADDRESS"); !search.empty())
    {
        world.search = search;
    }
    const auto keySet = xitoken::KeySet::create(*identity, name, {}, xitoken::systemNow(), std::nullopt, world);

    auto gateway = std::unique_ptr<FederationGateway>(new FederationGateway(scheduler, ipcServer, std::move(*identity), trustDir, keySet));
    gateway->reloadTrust(true);
    ShowInfoFmt("Federation gateway: world {} ({}) at {}, trusting {} provider(s) from {}",
                gateway->serverId_,
                name,
                publicUrl,
                gateway->keys_.size(),
                trustDir);
    return gateway;
}

FederationGateway::FederationGateway(Scheduler& scheduler, IPCServer& ipcServer, xitoken::SigningKey identity, std::string trustDir, std::string keySet)
: scheduler_(scheduler)
, ipcServer_(ipcServer)
, identity_(std::move(identity))
, serverId_(identity_.serverId())
, trustDir_(std::move(trustDir))
, keySet_(std::move(keySet))
, verifier_(keys_, xitoken::VerifierOptions{ .audience = serverId_, .replayGuard = &replay_ })
{
}

void FederationGateway::registerRoutes(httplib::Server& server)
{
    auto send = [](httplib::Response& res, const Reply& reply)
    {
        res.status = reply.first;
        res.set_content(reply.second.dump(), "application/json");
    };

    server.Get("/xi/v1/keyset",
               [this](const httplib::Request&, httplib::Response& res)
               {
                   res.set_content(keySet_, "text/plain");
               });

    server.Post("/xi/v1/world-entry",
                [this, send](const httplib::Request& req, httplib::Response& res)
                {
                    send(res, worldEntry(req.body, req.remote_addr));
                });

    server.Get("/xi/v1/characters",
               [this, send](const httplib::Request& req, httplib::Response& res)
               {
                   Reply rejection;
                   if (auto player = authenticate(req, rejection))
                   {
                       send(res, listCharacters(*player));
                       return;
                   }
                   send(res, rejection);
               });

    server.Post("/xi/v1/characters",
                [this, send](const httplib::Request& req, httplib::Response& res)
                {
                    Reply rejection;
                    if (auto player = authenticate(req, rejection))
                    {
                        send(res, createCharacter(*player, req.body));
                        return;
                    }
                    send(res, rejection);
                });

    server.Delete(R"(/xi/v1/characters/(\d{1,10}))",
                  [this, send](const httplib::Request& req, httplib::Response& res)
                  {
                      Reply rejection;
                      if (auto player = authenticate(req, rejection))
                      {
                          send(res, deleteCharacter(*player, static_cast<uint32>(std::stoull(req.matches[1].str()))));
                          return;
                      }
                      send(res, rejection);
                  });

    server.Post(R"(/xi/v1/characters/(\d{1,10})/name)",
                [this, send](const httplib::Request& req, httplib::Response& res)
                {
                    Reply rejection;
                    if (auto player = authenticate(req, rejection))
                    {
                        send(res, renameCharacter(*player, static_cast<uint32>(std::stoull(req.matches[1].str())), req.body));
                        return;
                    }
                    send(res, rejection);
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

auto FederationGateway::authenticate(const httplib::Request& req, Reply& rejection) -> std::optional<xitoken::Token>
{
    reloadTrust(false);

    constexpr std::string_view scheme = "XiToken ";
    const auto                 header = req.get_header_value("Authorization");
    if (header.compare(0, scheme.size(), scheme) != 0)
    {
        rejection = reply(400, "malformed");
        return std::nullopt;
    }
    auto result = verifier_.verify(std::string_view(header).substr(scheme.size()), "xi.account/1");
    if (!result)
    {
        ShowWarningFmt("Federation gateway: rejected account call from {}: {}", req.remote_addr, xitoken::toString(result.error));
        rejection = reply(400, xitoken::toString(result.error));
        return std::nullopt;
    }
    return std::move(result.token);
}

auto FederationGateway::findAccount(const xitoken::Token& player) -> std::optional<Account>
{
    const auto rset = db::preparedStmt("SELECT f.accid, a.status FROM accounts_federated f JOIN accounts a ON a.id = f.accid "
                                       "WHERE f.provider = ? AND f.subject = ? LIMIT 1",
                                       player.issuer,
                                       player.subject);
    if (!rset || !rset->next())
    {
        return std::nullopt;
    }
    return Account{ rset->get<uint32>("accid"), rset->get<uint8>("status") };
}

// A player's first character on this world makes their account: an LSB account no password can open (its login is
// random and its password is not a hash), mapped to the player's global id.
auto FederationGateway::createAccount(const xitoken::Token& player) -> std::optional<Account>
{
    uint8 random[9];
    if (RAND_bytes(random, sizeof(random)) != 1)
    {
        return std::nullopt;
    }
    const auto login = "fed:" + xitoken::base64url::encode(random, sizeof(random)); // 16 characters, the column's size

    db::preparedStmt("INSERT INTO accounts(id, login, password, timecreate, timelastmodify, status, priv) "
                     "SELECT GREATEST(COALESCE(MAX(id), 0) + 1, 1000), ?, '!fed', NOW(), NOW(), 1, 1 FROM accounts",
                     login);
    const auto rset = db::preparedStmt("SELECT id FROM accounts WHERE login = ? LIMIT 1", login);
    if (!rset || !rset->next())
    {
        return std::nullopt;
    }
    const auto accid = rset->get<uint32>("id");
    db::preparedStmt("INSERT IGNORE INTO accounts_federated(provider, subject, accid) VALUES(?, ?, ?)", player.issuer, player.subject, accid);

    // A concurrent call may have mapped the player first; its account wins and ours goes.
    auto account = findAccount(player);
    if (!account || account->accid != accid)
    {
        db::preparedStmt("DELETE FROM accounts WHERE id = ? AND login = ?", accid, login);
    }
    else
    {
        ShowInfoFmt("Federation gateway: created account {} for {}", accid, player.playerId());
    }
    return account;
}

auto FederationGateway::onMainThread(std::function<Reply()> fn) -> Reply
{
    auto promise = std::make_shared<std::promise<Reply>>();
    auto future  = promise->get_future();
    scheduler_.postToMainThread(
        [promise, fn = std::move(fn)]()
        {
            try
            {
                promise->set_value(fn());
            }
            catch (const std::exception& e)
            {
                ShowErrorFmt("Federation gateway: {}", e.what());
                promise->set_value(reply(500, "internal_error"));
            }
        });
    if (future.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
    {
        return reply(503, "unavailable");
    }
    return future.get();
}

auto FederationGateway::listCharacters(const xitoken::Token& player) -> Reply
{
    json list    = json::array();
    auto account = findAccount(player);
    if (!account)
    {
        return ok({ { "characters", list } });
    }

    const auto rset = db::preparedStmt("SELECT c.charid, c.charname, c.doRename, IF(c.pos_zone = 0, c.pos_prevzone, c.pos_zone) AS zone, "
                                       "c.nation, c.gmlevel, s.mjob, s.sjob, l.race, l.face, l.size, "
                                       "l.head, l.body, l.hands, l.legs, l.feet, l.main, l.sub, "
                                       "CAST(ELT(s.mjob, j.war, j.mnk, j.whm, j.blm, j.rdm, j.thf, j.pld, j.drk, j.bst, j.brd, j.rng, "
                                       "j.sam, j.nin, j.drg, j.smn, j.blu, j.cor, j.pup, j.dnc, j.sch, j.geo, j.run) AS UNSIGNED) AS mlvl "
                                       "FROM chars c "
                                       "JOIN char_stats s ON s.charid = c.charid "
                                       "JOIN char_look l ON l.charid = c.charid "
                                       "JOIN char_jobs j ON j.charid = c.charid "
                                       "WHERE c.accid = ? ORDER BY c.charid",
                                       account->accid);
    FOR_DB_MULTIPLE_RESULTS(rset)
    {
        list.push_back({
            { "id", rset->get<uint32>("charid") },
            { "name", rset->get<std::string>("charname") },
            { "rename", rset->get<uint8>("doRename") != 0 },
            { "zone", rset->get<uint16>("zone") },
            { "nation", rset->get<uint8>("nation") },
            { "race", rset->get<uint8>("race") },
            { "face", rset->get<uint8>("face") },
            { "size", rset->get<uint8>("size") },
            { "gm", rset->get<uint8>("gmlevel") > 0 },
            { "job", { { "main", rset->get<uint8>("mjob") }, { "main_level", rset->get<uint8>("mlvl") }, { "sub", rset->get<uint8>("sjob") } } },
            { "look",
              { { "head", rset->get<uint16>("head") },
                { "body", rset->get<uint16>("body") },
                { "hands", rset->get<uint16>("hands") },
                { "legs", rset->get<uint16>("legs") },
                { "feet", rset->get<uint16>("feet") },
                { "main", rset->get<uint16>("main") },
                { "sub", rset->get<uint16>("sub") } } },
        });
    }
    return ok({ { "characters", list } });
}

auto FederationGateway::createCharacter(const xitoken::Token& player, const std::string& body) -> Reply
{
    json request = json::parse(body, nullptr, false);
    if (!request.is_object() || !request.contains("name") || !request["name"].is_string())
    {
        return reply(400, "bad_request");
    }
    const auto name   = request["name"].get<std::string>();
    const auto race   = getUInt(request, "race", 8);
    const auto face   = getUInt(request, "face", 15);
    const auto size   = getUInt(request, "size", 2);
    const auto job    = getUInt(request, "job", 6);
    const auto nation = getUInt(request, "nation", 2);
    if (!race || *race < 1 || !face || !size || !job || *job < 1 || !nation)
    {
        return reply(400, "bad_request");
    }

    // Name checks read the Lua settings (banned words), which belong to the main thread.
    return onMainThread(
        [=, this]() -> Reply
        {
            if (const auto reason = loginHelpers::validateCharacterName(name))
            {
                return reply(409, nameError(*reason));
            }

            auto account = findAccount(player);
            if (!account)
            {
                account = createAccount(player);
            }
            if (!account)
            {
                return reply(503, "unavailable");
            }
            if (!(account->status & ACCOUNT_STATUS_NORMAL))
            {
                return reply(409, "not_permitted");
            }
            // Maintenance, creation switched off, or the account's character slots (accounts.content_ids) are full.
            if (loginHelpers::characterCreationError(account->accid, name))
            {
                return reply(409, "not_permitted");
            }

            // The next free id that fits 16 bits; past 0xFFFF, the lowest gap.
            uint32 charId = 0;
            if (const auto rset = db::preparedStmt("SELECT COALESCE(MAX(charid), 0) + 1 AS next FROM chars WHERE charid <= ?", MAX_CHARID); rset && rset->next())
            {
                charId = rset->get<uint32>("next");
            }
            if (charId == 0 || charId > MAX_CHARID)
            {
                const auto gap = db::preparedStmt("SELECT MIN(c.charid) + 1 AS next FROM chars c "
                                                  "WHERE c.charid < ? AND NOT EXISTS (SELECT 1 FROM chars n WHERE n.charid = c.charid + 1)",
                                                  MAX_CHARID);
                charId = gap && gap->next() ? gap->get<uint32>("next") : 0;
                if (charId == 0 || charId > MAX_CHARID)
                {
                    return reply(409, "full");
                }
            }

            static const std::vector<xi::ZoneId> startingZones[] = {
                { xi::ZoneId::SouthernSanDoria, xi::ZoneId::NorthernSanDoria, xi::ZoneId::PortSanDoria },
                { xi::ZoneId::BastokMines, xi::ZoneId::BastokMarkets, xi::ZoneId::PortBastok },
                { xi::ZoneId::WindurstWaters, xi::ZoneId::PortWindurst, xi::ZoneId::WindurstWoods },
            };

            char_mini character{};
            std::memcpy(character.m_name, name.c_str(), std::min<size_t>(name.size(), sizeof(character.m_name) - 1));
            character.m_mjob      = static_cast<uint8>(*job);
            character.m_nation    = static_cast<uint8>(*nation);
            character.m_zone      = startingZones[*nation][xirand::GetRandomNumber(3)];
            character.m_look.race = static_cast<uint8>(*race);
            character.m_look.face = static_cast<uint8>(*face);
            character.m_look.size = static_cast<uint16>(*size);

            if (loginHelpers::saveCharacter(account->accid, charId, &character) == -1)
            {
                return reply(409, "name_taken"); // the name or id was taken between the checks and the insert
            }
            ShowInfoFmt("Federation gateway: {} created character {} ({}) on account {}", player.playerId(), name, charId, account->accid);
            return ok({ { "id", charId } });
        });
}

auto FederationGateway::deleteCharacter(const xitoken::Token& player, uint32 charId) -> Reply
{
    auto account = findAccount(player);
    if (!account)
    {
        return reply(404, "unknown_character");
    }
    if (!settings::get<bool>("login.CHARACTER_DELETION") || !(account->status & ACCOUNT_STATUS_NORMAL))
    {
        return reply(409, "not_permitted");
    }
    // As xi_connect does: keep the row (and every char_* row) and detach it from the account.
    const auto rset = db::preparedStmt("UPDATE chars SET original_accid = accid, accid = 0 WHERE charid = ? AND accid = ?", charId, account->accid);
    if (!rset || rset->rowsAffected() != 1)
    {
        return reply(404, "unknown_character");
    }
    db::preparedStmt("DELETE FROM accounts_sessions WHERE charid = ?", charId);
    ShowInfoFmt("Federation gateway: {} deleted character {}", player.playerId(), charId);
    return ok();
}

auto FederationGateway::renameCharacter(const xitoken::Token& player, uint32 charId, const std::string& body) -> Reply
{
    json request = json::parse(body, nullptr, false);
    if (!request.is_object() || !request.contains("name") || !request["name"].is_string())
    {
        return reply(400, "bad_request");
    }
    const auto name = request["name"].get<std::string>();

    return onMainThread(
        [=, this]() -> Reply
        {
            auto account = findAccount(player);
            if (!account)
            {
                return reply(404, "unknown_character");
            }
            const auto rset = db::preparedStmt("SELECT doRename FROM chars WHERE charid = ? AND accid = ? LIMIT 1", charId, account->accid);
            if (!rset || !rset->next())
            {
                return reply(404, "unknown_character");
            }
            if (rset->get<uint8>("doRename") == 0 || !(account->status & ACCOUNT_STATUS_NORMAL))
            {
                return reply(409, "not_permitted");
            }
            if (const auto reason = loginHelpers::validateCharacterName(name))
            {
                return reply(409, nameError(*reason));
            }
            db::preparedStmt("UPDATE chars SET charname = ?, doRename = 0 WHERE charid = ? AND accid = ?", name, charId, account->accid);
            ShowInfoFmt("Federation gateway: {} renamed character {} to {}", player.playerId(), charId, name);
            return ok();
        });
}

auto FederationGateway::worldEntry(const std::string& token, const std::string& peer) -> Reply
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

    // The player's account on this world.
    auto account = findAccount(*result.token);
    if (!account || !(account->status & ACCOUNT_STATUS_NORMAL))
    {
        ShowWarningFmt("Federation gateway: {} has no usable account on this world", result.token->playerId());
        return reply(409, "not_permitted");
    }
    const uint32 accid = account->accid;

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

    return ok({ { "map", { { "ip", zoneIp }, { "port", zonePort } } } });
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
