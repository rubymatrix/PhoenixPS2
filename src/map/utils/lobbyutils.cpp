/*
===========================================================================

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

#include "lobbyutils.h"

#include "common/logging.h"
#include "common/settings.h"

#include "entities/char_entity.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace lobbyutils
{

namespace
{

// The account service answers from its own database queries on localhost or a private network
constexpr time_t ConnectTimeoutSeconds = 1;
constexpr time_t ReadTimeoutSeconds    = 2;

void useOwnContentId(CCharEntity* PChar)
{
    PChar->account = PChar->accid;
    PChar->accountContentIds.clear();
}

} // namespace

void loadAccount(CCharEntity* PChar, const std::string& lobbyToken)
{
    useOwnContentId(PChar);

    const auto url = settings::get<std::string>("network.LOBBY_ACCOUNTS_URL");
    const auto key = settings::get<std::string>("network.LOBBY_ACCOUNTS_KEY");
    if (url.empty() || key.empty())
    {
        return;
    }

    if (lobbyToken.empty())
    {
        ShowWarningFmt("lobbyutils: {} ({}) has no lobby session token; account limits apply to the character alone", PChar->getName(), PChar->id);
        return;
    }

    httplib::Client client(url);
    client.set_connection_timeout(ConnectTimeoutSeconds);
    client.set_read_timeout(ReadTimeoutSeconds);

    const httplib::Headers headers{
        { "Authorization", "Bearer " + key },
        { "X-Lobby-Session", lobbyToken },
    };

    const auto result = client.Get("/v1/session", headers);
    if (!result)
    {
        ShowWarningFmt("lobbyutils: account service at {} unreachable ({}) for {} ({}); account limits apply to the character alone",
                       url,
                       httplib::to_string(result.error()),
                       PChar->getName(),
                       PChar->id);
        return;
    }

    if (result->status != 200)
    {
        ShowWarningFmt("lobbyutils: account service refused {} ({}): HTTP {}; account limits apply to the character alone", PChar->getName(), PChar->id, result->status);
        return;
    }

    try
    {
        const auto answer     = nlohmann::json::parse(result->body);
        const auto contentId  = answer.at("contentId").get<uint32>();
        const auto account    = answer.at("account").get<uint32>();
        const auto contentIds = answer.at("contentIds").get<std::vector<uint32>>();

        // The session the token names has to be this character's
        if (contentId != PChar->accid || account == 0 || std::ranges::find(contentIds, contentId) == contentIds.end())
        {
            ShowWarningFmt("lobbyutils: account service answered for content id {}, not {} ({}) on content id {}", contentId, PChar->getName(), PChar->id, PChar->accid);
            return;
        }

        PChar->account           = account;
        PChar->accountContentIds = contentIds;
    }
    catch (const nlohmann::json::exception& e)
    {
        ShowWarningFmt("lobbyutils: account service answer for {} ({}) unreadable: {}", PChar->getName(), PChar->id, e.what());
    }
}

auto isSameAccount(const CCharEntity* PChar, const uint32 contentId) -> bool
{
    return contentId != 0 && std::ranges::find(PChar->accountContentIds, contentId) != PChar->accountContentIds.end();
}

} // namespace lobbyutils
