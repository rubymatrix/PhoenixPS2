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

#pragma once

#include "common/cbasetypes.h"

#include <string>

class CCharEntity;

// The PlayOnline lobby owns accounts; the world knows a character by its content id (chars.accid) only. Which
// PlayOnline member a character belongs to comes from the lobby's account service, asked with the token the lobby
// wrote into the character's session row (accounts_sessions.lobby_token), which lives as long as the session.
namespace lobbyutils
{

// Fills PChar->account and PChar->accountContentIds. Without an answer (no service configured, no token, lobby
// unreachable or refusing): the account is the character's own content id and it shares nothing.
void loadAccount(CCharEntity* PChar, const std::string& lobbyToken);

// Whether a content id belongs to the same PlayOnline member as the character (never without the lobby's answer)
auto isSameAccount(const CCharEntity* PChar, uint32 contentId) -> bool;

} // namespace lobbyutils
