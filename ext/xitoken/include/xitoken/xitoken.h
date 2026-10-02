// xitoken — short-lived signed tokens (PASETO v4.public) between POL providers and FFXI worlds.
// See SPEC.md. Dependencies: OpenSSL 3 (libcrypto) and nlohmann/json. C++17.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace xitoken
{

using Bytes = std::vector<uint8_t>;
using Key32 = std::array<uint8_t, 32>;

// ---------------------------------------------------------------------------------------------------------------
// Encodings

namespace base64url
{
    auto encode(const uint8_t* data, size_t size) -> std::string;
    inline auto encode(const Bytes& data) -> std::string { return encode(data.data(), data.size()); }
    inline auto encode(std::string_view data) -> std::string { return encode(reinterpret_cast<const uint8_t*>(data.data()), data.size()); }
    // Strict: unpadded, no whitespace, canonical trailing bits.
    auto decode(std::string_view text) -> std::optional<Bytes>;
} // namespace base64url

namespace rfc3339
{
    // Writes YYYY-MM-DDTHH:MM:SSZ.
    auto format(int64_t unixSeconds) -> std::string;
    // Any offset; fractional seconds are truncated.
    auto parse(std::string_view text) -> std::optional<int64_t>;
} // namespace rfc3339

// ---------------------------------------------------------------------------------------------------------------
// Keys

auto isValidKeyId(std::string_view kid) -> bool;

class SigningKey
{
public:
    static auto generate(std::string kid) -> std::optional<SigningKey>;
    static auto fromSeed(std::string kid, const Key32& seed) -> std::optional<SigningKey>;
    static auto fromPaserk(std::string kid, std::string_view k4secret) -> std::optional<SigningKey>; // "k4.secret...."

    auto keyId() const -> const std::string& { return kid_; }
    auto seed() const -> const Key32& { return seed_; }
    auto publicKey() const -> const Key32& { return pub_; }
    auto paserkSecret() const -> std::string;
    auto paserkPublic() const -> std::string;
    auto serverId() const -> std::string; // the id this key stands for when used as an identity key

private:
    std::string kid_;
    Key32       seed_{};
    Key32       pub_{};
};

auto decodePaserkPublic(std::string_view k4public) -> std::optional<Key32>;

// Server ids (SPEC.md "Server ids"): "xi1." + base64url(SHA-256("xitoken server id\0" || identity public key)[0..16]).
auto serverIdFromPublicKey(const Key32& identityPublicKey) -> std::string;
auto isValidServerId(std::string_view id) -> bool;
// A player's global id: "<provider server id>:<sub>".
inline auto playerId(const std::string& providerId, const std::string& subject) -> std::string { return providerId + ":" + subject; }

struct TrustedKey
{
    std::string issuer; // server id
    std::string kid;
    Key32       publicKey{};
};

class KeyResolver
{
public:
    virtual ~KeyResolver()                                                                       = default;
    virtual auto find(const std::string& issuer, const std::string& kid) const -> std::optional<TrustedKey> = 0;
};

// The opened contents of a signed key set (SPEC.md "Keys and key sets").
// What a world's key set says about the world (SPEC.md "Keys and key sets").
struct WorldInfo
{
    std::string                gateway;
    uint32_t                   expansions = 0;
    std::optional<std::string> search; // the world's search server as "IPv4:port"
};

// The opened contents of a signed key set (SPEC.md "Keys and key sets").
struct KeySet
{
    static constexpr std::string_view type = "xi.keyset/1";

    std::string                serverId;
    std::optional<std::string> name;
    int64_t                    issuedAt = 0;
    std::optional<int64_t>     expires;
    std::vector<TrustedKey>    keys;
    std::optional<WorldInfo>   world;

    // Signs a key set with the server's identity key. Worlds pass `world`.
    static auto create(const SigningKey& identity, const std::optional<std::string>& name, const std::vector<SigningKey>& signingKeys,
                       int64_t issuedAt, std::optional<int64_t> expires = std::nullopt, const std::optional<WorldInfo>& world = std::nullopt)
        -> std::string;
    // Checks a signed key set; nullopt (and *error) if it is not valid at `now`.
    static auto open(std::string_view token, int64_t now, std::string* error = nullptr) -> std::optional<KeySet>;
};

// One server listed in a registry.
struct RegistryEntry
{
    std::string                id;
    std::string                role; // "world" or "provider"
    std::string                keysetUrl;
    std::optional<std::string> pin;
};

// A signed list of servers (SPEC.md "World list and registry"). Listing only says where to find a server; its key
// set is still checked against its id.
struct Registry
{
    static constexpr std::string_view type = "xi.registry/1";

    std::string                serverId;
    std::optional<std::string> name;
    int64_t                    issuedAt = 0;
    std::optional<int64_t>     expires;
    std::vector<RegistryEntry> servers;

    static auto create(const SigningKey& identity, const std::optional<std::string>& name, const std::vector<RegistryEntry>& servers,
                       int64_t issuedAt, std::optional<int64_t> expires = std::nullopt) -> std::string;
    // Opens a registry, but only if it belongs to `expectedServerId`; nullopt (and *error) otherwise.
    static auto open(std::string_view token, const std::string& expectedServerId, int64_t now, std::string* error = nullptr)
        -> std::optional<Registry>;
};

// Key resolver built from the signed key sets of the servers an operator chose to trust. Thread-safe.
class KeySetResolver : public KeyResolver
{
public:
    auto find(const std::string& issuer, const std::string& kid) const -> std::optional<TrustedKey> override;

    // Trusts the key set's keys only if it belongs to `expectedServerId` and is not older than the one loaded.
    // Returns false and changes nothing on error; *error explains why. `now` < 0 means systemNow().
    auto trust(std::string_view token, const std::string& expectedServerId, int64_t now = -1, std::string* error = nullptr) -> bool;
    auto trustFile(const std::string& path, const std::string& expectedServerId, int64_t now = -1, std::string* error = nullptr) -> bool;

    auto size() const -> size_t;

private:
    mutable std::mutex                      mutex_;
    std::unordered_map<std::string, KeySet> sets_;
};

// ---------------------------------------------------------------------------------------------------------------
// PASETO v4.public

namespace paseto
{
    constexpr std::string_view header        = "v4.public.";
    constexpr size_t           signatureSize = 64;
    constexpr size_t           maxTokenSize  = 8192;

    auto pae(const std::vector<std::string_view>& pieces) -> std::string;
    auto sign(const SigningKey& key, std::string_view payload, std::string_view footer, std::string_view implicitAssertion = {}) -> std::string;

    struct Parts
    {
        std::string payload;
        std::string signature;
        std::string footer; // untrusted until verify() succeeds
    };
    auto parse(std::string_view token) -> std::optional<Parts>;
    // Returns the payload and footer only if the signature is valid.
    auto verify(std::string_view token, const Key32& publicKey, std::string_view implicitAssertion = {}) -> std::optional<Parts>;
} // namespace paseto

// ---------------------------------------------------------------------------------------------------------------
// Tokens

enum class Error
{
    None,
    Malformed,
    UnknownKey,
    BadSignature,
    BadClaims,
    WrongIssuer,
    WrongAudience,
    WrongType,
    NotYetValid,
    Expired,
    LifetimeTooLong,
    Replayed,
};

auto toString(Error error) -> const char*; // "ok", "malformed", "unknown_key", ...

// Remembers consumed token ids. Worlds with several processes need a shared one (e.g. a DB table keyed on issuer + jti).
class ReplayGuard
{
public:
    virtual ~ReplayGuard() = default;
    // Records the id and returns true, or returns false if it was already recorded.
    virtual auto tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool = 0;
};

class MemoryReplayGuard : public ReplayGuard
{
public:
    explicit MemoryReplayGuard(std::function<int64_t()> now = {});
    auto tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool override;

private:
    std::function<int64_t()>                 now_;
    std::mutex                               mutex_;
    std::unordered_map<std::string, int64_t> seen_;
};

auto systemNow() -> int64_t; // unix seconds

struct Token
{
    std::string    issuer;
    std::string    audience;
    std::string    subject;
    std::string    type;
    std::string    id;
    std::string    kid;
    int64_t        issuedAt = 0;
    int64_t        expires  = 0;
    nlohmann::json claims; // the whole payload

    auto playerId() const -> std::string { return xitoken::playerId(issuer, subject); }
};

struct VerifyResult
{
    Error                error = Error::Malformed;
    std::optional<Token> token;

    explicit operator bool() const { return error == Error::None; }
};

struct VerifierOptions
{
    std::string              audience;          // this world's id
    int64_t                  clockSkew   = 30;  // seconds
    int64_t                  maxLifetime = 300; // seconds
    ReplayGuard*             replayGuard = nullptr; // required for single use; null disables it (tests only)
    std::function<int64_t()> now;               // defaults to systemNow
};

class Verifier
{
public:
    static constexpr size_t maxFooterSize = 512;
    static constexpr int    maxJsonDepth  = 32;

    Verifier(const KeyResolver& keys, VerifierOptions options);
    auto verify(std::string_view token, std::string_view expectedType) const -> VerifyResult;

private:
    const KeyResolver& keys_;
    VerifierOptions    options_;
};

class Issuer
{
public:
    // `serverId` is this provider's id; `key` is a signing key listed in its published key set. Throws on a bad id.
    Issuer(std::string serverId, SigningKey key);
    // `claims` holds type-specific claims and may not set registered ones. `now` < 0 means systemNow().
    auto issue(const std::string& type, const std::string& audience, const std::string& subject, int64_t lifetimeSeconds,
               const nlohmann::json& claims = nlohmann::json::object(), int64_t now = -1) const -> std::string;

private:
    std::string issuer_;
    SigningKey  key_;
};

// ---------------------------------------------------------------------------------------------------------------
// xi.world-entry/1

struct WorldEntry
{
    static constexpr std::string_view type            = "xi.world-entry/1";
    static constexpr int64_t          defaultLifetime = 60;

    uint32_t                   charId = 0;
    std::optional<std::string> charName;
    std::string                clientIp;      // dotted IPv4
    std::string                clientVersion; // <= 16 chars
    uint32_t                   clientExpansions = 0;
    std::array<uint8_t, 20>    sessionKey{};  // live secret: never log

    auto toClaims() const -> nlohmann::json;
    static auto fromClaims(const nlohmann::json& claims) -> std::optional<WorldEntry>;

    // The client address as LSB stores it in accounts_sessions.client_addr (first octet in the low byte).
    auto clientAddrLsb() const -> uint32_t;
};

} // namespace xitoken
