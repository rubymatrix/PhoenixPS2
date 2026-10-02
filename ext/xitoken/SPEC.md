# xitoken — short-lived signed tokens between POL providers and FFXI worlds

Version 1. This document is normative; the C# (`dotnet/`) and C++ (`cpp/`) libraries are reference
implementations, and `vectors/` holds the test vectors every implementation must pass.

## Why

Today a world trusts a lobby because the lobby can write `accounts_sessions` rows into the world's database.
That does not work once worlds are run by different operators. Instead, the **provider** (the POL service the
player signed in to: auth + lobby, e.g. Project Crystal) hands a **world** a token that says, signed with the
provider's key, "this player, on this world, for the next minute". The world checks the signature with the
provider's public key and never shares a database or a secret with it.

| role | does | holds |
|---|---|---|
| provider | authenticates players, issues tokens | an identity key, and the signing keys it endorses |
| world | verifies tokens, admits players | an identity key (for its id), and the provider ids it chose to trust |

## Server ids

Every server — provider or world — has a long-lived Ed25519 **identity key**. Its **server id** is derived from
the identity public key, so ids are globally unique without a registry, and only the key's holder can speak for
an id:

    server id = "xi1." + base64url( SHA-256( "xitoken server id" || 0x00 || identity_public_key )[0..16] )

That is `xi1.` followed by 22 characters, for example `xi1.3q2-7wGHFgjEVK8bq0iNcw`.

* Tokens use server ids for `iss` (the provider) and `aud` (the world).
* A player's **global id** is `<provider server id>:<sub>`. For example, `xi1.3q2-7wGHFgjEVK8bq0iNcw:1001` is
  player `1001` at that provider. A server id never contains `:`, so the global id splits at the first `:`.
* Display names ("Crystal", "PhoenixPS2") are labels carried alongside the id. Nothing trusts them.
* The identity key only signs key sets, so it can be kept offline. Losing or replacing it means a new server id.

## Keys and key sets

* Secret keys are written as PASERK `k4.secret.<base64url(seed32 || public32)>`, public keys as
  `k4.public.<base64url(public32)>`.
* A server signs tokens with **signing keys**, each named by a **key id** (`kid`): 1–64 characters from
  `[A-Za-z0-9._:-]`, unique within that server (for example `2026-10`).
* The server publishes its signing keys as a **signed key set**: a v4.public token signed by its identity key.

Footer:

```json
{ "idk": "k4.public.<identity public key>" }
```

Payload:

```json
{
  "typ": "xi.keyset/1",
  "iss": "xi1.3q2-7wGHFgjEVK8bq0iNcw",
  "name": "Crystal",
  "iat": "2026-10-01T12:00:00Z",
  "keys": [ { "kid": "2026-10", "public": "k4.public.HrnbmBN..." } ]
}
```

`name` is optional. `exp` is optional; when it is present, the key set stops being accepted after it.

A world's key set also describes the world, in an optional `world` member. Because it is signed, a provider can
take it from anywhere and still trust it as much as the world's id:

```json
"world": { "gateway": "https://ps2.example.net:8088", "expansions": 4095, "search": "203.0.113.7:54002" }
```

| field | meaning |
|---|---|
| `gateway` | base URL of the world's gateway (see "World gateway API") |
| `search` | optional: the world's search server as `IPv4:port`, which the provider gives the client with the map server |
| `expansions` | the expansions the world enables, as the FFXI lobby's expansion bitmask: 0x0001 base game, 0x0002 RoZ, 0x0004 CoP, 0x0008 ToAU, 0x0010 WotG, 0x0020 ACP, 0x0040 MKE, 0x0080 ASA, 0x0100/0x0200/0x0400 Abyssea, 0x0800 SoA |

Every server serves its current key set at `GET <base>/xi/v1/keyset` (`text/plain`, no authentication). For a
world, `<base>` is its gateway.

To load a key set, a server:

1. decodes `idk` and computes its server id;
2. checks the signature with `idk`;
3. checks that `typ` is `xi.keyset/1`, that `iss` equals the computed id, and that `iss` equals the id the operator
   chose to trust;
4. checks that every `kid` is valid and unique within the set.

Because the key set authenticates itself, it can be fetched from anywhere: a file, a web page, or a registry.
The trust decision is only the server id.

When a newer key set (later `iat`) for the same id is loaded, it replaces the older one.

Rotation: publish a key set with the new key added, wait for worlds to reload it, start signing with the new key,
then publish one without the old key once the longest token lifetime has passed. Revocation: publish a key set
without the key.

## Token format

A token is a [PASETO](https://github.com/paseto-standard/paseto-spec) **v4.public** token (Ed25519):

    v4.public.<base64url(payload || signature)>.<base64url(footer)>

* Base64url without padding. A token is at most 8192 characters.
* No implicit assertion is used (empty string).
* **Footer** (required): `{"iss":"<server id>","kid":"<key id>"}`, at most 512 bytes. It is unauthenticated until
  the signature is checked; it is used only to pick the key.
* **Payload**: a UTF-8 JSON object, at most 32 levels deep, with no duplicate keys.

Implementations MUST pass `vectors/paseto-v4-public.json` (the upstream v4.public vectors) before anything else.

## Claims

All times are RFC 3339 strings. Issuers write `YYYY-MM-DDTHH:MM:SSZ`; verifiers accept any RFC 3339 offset and
fractional seconds (which they truncate).

| claim | required | meaning |
|---|---|---|
| `iss` | yes | provider server id. MUST equal the id whose key set holds the signing key |
| `aud` | yes | world server id the token is for |
| `sub` | yes | the player's account id **at the provider** (string). `iss:sub` is the player's global id |
| `typ` | yes | token type, see below. A verifier only accepts the type it asked for |
| `jti` | yes | unique token id: at least 128 random bits, base64url (issuers use 22 chars = 16 bytes) |
| `iat` | yes | issued at |
| `exp` | yes | expires at. `exp - iat` MUST NOT exceed the verifier's maximum lifetime |
| `nbf` | no | not before |

Other claims belong to the token type.

### Verification

Run the steps in this order and stop at the first failure. The error names are the ones the libraries return.

1. Parse: `v4.public.` header, base64url, payload of at least 64 bytes, footer present with string `iss` and
   `kid` → else `malformed`.
2. Look up the footer's `(iss, kid)` among trusted key sets → else `unknown_key`.
3. Check the Ed25519 signature over `PAE("v4.public.", payload, footer, "")` → else `bad_signature`.
4. Decode the JSON payload and check that every required claim is present with the right type → else `bad_claims`.
5. Check that the payload's `iss` equals the key's server id → else `wrong_issuer`. This stops one provider's key
   from minting tokens in another provider's name.
6. Check that `aud` equals this world's id → else `wrong_audience`.
7. Check that `typ` equals the expected type → else `wrong_type`.
8. Time, with a clock skew allowance `s` (default 30 s):
   * `now + s < nbf` (when `nbf` is present) or `now + s < iat` → `not_yet_valid`
   * `now - s >= exp` → `expired`
   * `exp - iat > max_lifetime` (default 300 s) → `lifetime_too_long`
9. Consume `(iss, jti)` in the replay guard. If it was already used → `replayed`. Entries are kept until
   `exp + s`. A world with several processes MUST share one guard (for example a table with a primary key on
   `(iss, jti)`).

The replay step comes last so that invalid tokens cannot fill the guard.

## Token types

### `xi.world-entry/1` — admit a character to a world

Issued by the provider's lobby when the player picks a character. It is sent to the world before the client
connects to the map server. Recommended lifetime: **60 s**.

| claim | type | meaning |
|---|---|---|
| `char` | object | `{"id": uint32, "name": string (optional)}`. The world's character id, which the lobby got from the world |
| `client` | object | `{"ip": dotted IPv4, "version": string ≤ 16, "expansions": uint32}`. Where the client will connect from, and its build (for consoles: `patch.ver` and the installed-expansion bits) |
| `skey` | string | base64url of the 20-byte map session key. The client derives its Blowfish key from it |

`skey` is a live secret. A world-entry token is signed, **not encrypted**, so it MUST only travel over a
confidential channel (TLS, or a loopback/private link). It MUST NOT be logged.

A world that accepts a world-entry token writes its own session row from these claims (in LSB terms, an
`accounts_sessions` row with `session_key`, `client_addr`, `client_version`, `client_expansions`). From that
point the map login is unchanged.

### `xi.account/1` — act for a signed-in player

For world APIs called on behalf of a player (list, create, delete or rename characters). It has no extra claims.
Recommended lifetime: **120 s**. The world maps the player's global id to its own account.

## World gateway API

A world accepts tokens over HTTPS, or plain HTTP on a loopback or private link:

    POST <gateway>/xi/v1/world-entry
    Content-Type: text/plain

    v4.public....

Before writing the session, the world checks four things:

* the token passes verification;
* the character exists;
* the character belongs to the account the world maps to the player's global id `iss:sub`;
* the world's own login rules allow it (ban status, one session per account, login limits, maintenance mode).

| status | body | meaning |
|---|---|---|
| 200 | `{"ok":true,"map":{"ip":"a.b.c.d","port":n}}` | session written. The provider sends the client to this map server, the one serving the character's zone |
| 400 | `{"ok":false,"error":"<name>"}` | token rejected: a verification error name, or `bad_entry` for invalid world-entry claims |
| 409 | `{"ok":false,"error":"<reason>"}` | token valid, but the world refuses the entry: `unknown_character`, `not_permitted` (not the player's character, no account, or banned), `already_logged_in`, `login_limit` |
| 503 | `{"ok":false,"error":"unavailable"}` | the world cannot take entries right now (maintenance, no map server for the zone) |

A token that passes verification is consumed even if the world then refuses the entry. The provider issues a new
token for each attempt.

### Characters

These calls act for a signed-in player. Each request carries a fresh `xi.account/1` token addressed to the
world:

    Authorization: XiToken v4.public....

The world maps the player's global id (`iss:sub`) to one of its accounts. It creates that account, and the mapping,
when the player creates their first character there. Every call answers JSON, and errors use the same
`{"ok":false,"error":"<name>"}` shape: `400` for a rejected token or request, `404 unknown_character`, `409` for a
refusal.

`GET <gateway>/xi/v1/characters` lists the player's characters on this world:

```json
{ "ok": true, "characters": [ {
    "id": 4097, "name": "Ayame", "rename": false,
    "zone": 230, "nation": 0, "race": 2, "face": 4, "size": 1, "gm": false,
    "job": { "main": 1, "main_level": 30, "sub": 6 },
    "look": { "head": 0, "body": 8, "hands": 8, "legs": 8, "feet": 8, "main": 0, "sub": 0 }
} ] }
```

A player with no account on the world gets an empty list.

`POST <gateway>/xi/v1/characters` creates a character. The body is a JSON object:

```json
{ "name": "Ayame", "race": 2, "face": 4, "size": 1, "job": 1, "nation": 0 }
```

The world chooses the starting zone. It answers `200 {"ok":true,"id":4097}`, or one of these:

* `400 bad_request` for invalid fields;
* `409 name_taken`, `409 name_invalid`, `409 not_permitted` (creation disabled, or the account is banned);
* `409 full` when no character id is free.

Character ids fit in 16 bits, because the PlayOnline content sub id carries them.

`DELETE <gateway>/xi/v1/characters/<id>` deletes one of the player's characters and answers `200 {"ok":true}`.

`POST <gateway>/xi/v1/characters/<id>/name` renames a character the world has flagged for renaming. The body is
`{"name": "..."}`, and the answers are the same as for creation.

### Transport

Tokens carry claims about players, and world-entry tokens carry session keys, so a gateway MUST use TLS unless it
is reached over a loopback or private link. A world may use a self-signed certificate. A provider then pins it by
the base64url SHA-256 of the certificate's DER encoding (for example `pin: "sha256:Jx3…"`) instead of validating
a chain.

## World list and registry

A provider lists worlds to its players. For each world it needs the server id it trusts, plus the world's signed
key set, which names the world and its gateway. A provider may take worlds from a **registry**: a signed document
listing servers, published by whoever runs the federation. It is a v4.public token signed by the registry's
identity key, with the footer `{"idk": "k4.public..."}` and this payload:

```json
{
  "typ": "xi.registry/1",
  "iss": "xi1.<registry server id>",
  "name": "PS2 Federation",
  "iat": "2026-10-01T12:00:00Z",
  "servers": [
    { "id": "xi1.Mu9wtwpxwOsrgZyRkVr0Uw", "role": "world",
      "keyset": "https://ps2.example.net:8088/xi/v1/keyset", "pin": "sha256:Jx3…" },
    { "id": "xi1.aDtov18q_lxyuiZzRwvExw", "role": "provider",
      "keyset": "https://crystal.example.net/xi/v1/keyset" }
  ]
}
```

A registry is checked like a key set: `iss` must be the id of its `idk`, and the id the operator chose to trust.
`pin` is optional.

Listing a server in a registry only says where to find it. The entry's `id` is what is trusted, and the key set
fetched from `keyset` is still checked against that id. A registry operator can add or remove servers, but cannot
impersonate one.
