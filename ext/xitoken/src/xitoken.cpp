// xitoken — see xitoken.h and SPEC.md.
#include "xitoken/xitoken.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>

namespace xitoken
{

namespace
{
    using json = nlohmann::json;

    struct PkeyDeleter
    {
        void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
    };
    struct MdCtxDeleter
    {
        void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
    };
    using Pkey  = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
    using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

    auto bytesOf(std::string_view s) -> const uint8_t*
    {
        return reinterpret_cast<const uint8_t*>(s.data());
    }

    // Parses a JSON object with no duplicate keys and bounded depth; nullopt if it is anything else.
    auto parseObject(std::string_view text) -> std::optional<json>
    {
        std::vector<std::set<std::string>> keys;
        auto                                callback = [&](int depth, json::parse_event_t event, json& parsed) -> bool
        {
            if (depth > Verifier::maxJsonDepth)
            {
                throw std::runtime_error("too deep");
            }
            switch (event)
            {
                case json::parse_event_t::object_start:
                    keys.emplace_back();
                    break;
                case json::parse_event_t::object_end:
                    keys.pop_back();
                    break;
                case json::parse_event_t::key:
                    if (!keys.back().insert(parsed.get<std::string>()).second)
                    {
                        throw std::runtime_error("duplicate key");
                    }
                    break;
                default:
                    break;
            }
            return true;
        };
        try
        {
            json value = json::parse(text.begin(), text.end(), callback);
            if (value.is_object())
            {
                return value;
            }
        }
        catch (const std::exception&)
        {
        }
        return std::nullopt;
    }

    auto getString(const json& obj, const char* name) -> std::optional<std::string>
    {
        auto it = obj.find(name);
        if (it == obj.end() || !it->is_string())
        {
            return std::nullopt;
        }
        return it->get<std::string>();
    }

    auto getUInt32(const json& obj, const char* name) -> std::optional<uint32_t>
    {
        auto it = obj.find(name);
        if (it == obj.end() || !it->is_number_unsigned() || it->get<uint64_t>() > 0xFFFFFFFFull)
        {
            return std::nullopt;
        }
        return static_cast<uint32_t>(it->get<uint64_t>());
    }

    auto parseIPv4(std::string_view ip) -> std::optional<std::array<uint8_t, 4>>
    {
        std::array<uint8_t, 4> out{};
        size_t                 pos = 0;
        for (int i = 0; i < 4; ++i)
        {
            size_t start = pos;
            int    value = 0;
            while (pos < ip.size() && ip[pos] >= '0' && ip[pos] <= '9' && pos - start < 3)
            {
                value = value * 10 + (ip[pos++] - '0');
            }
            size_t len = pos - start;
            if (len == 0 || value > 255 || (len > 1 && ip[start] == '0'))
            {
                return std::nullopt;
            }
            out[i] = static_cast<uint8_t>(value);
            if (i < 3)
            {
                if (pos >= ip.size() || ip[pos] != '.')
                {
                    return std::nullopt;
                }
                ++pos;
            }
        }
        if (pos != ip.size())
        {
            return std::nullopt;
        }
        return out;
    }

    auto randomBytes(uint8_t* out, size_t size) -> bool
    {
        return RAND_bytes(out, static_cast<int>(size)) == 1;
    }

    auto publicFromSeed(const Key32& seed, Key32& pub) -> bool
    {
        Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
        size_t len = pub.size();
        return key && EVP_PKEY_get_raw_public_key(key.get(), pub.data(), &len) == 1 && len == pub.size();
    }
} // namespace

// ---------------------------------------------------------------------------------------------------------------
// base64url

namespace base64url
{
    namespace
    {
        constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        auto value(char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
            {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z')
            {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9')
            {
                return c - '0' + 52;
            }
            if (c == '-')
            {
                return 62;
            }
            if (c == '_')
            {
                return 63;
            }
            return -1;
        }
    } // namespace

    auto encode(const uint8_t* data, size_t size) -> std::string
    {
        std::string out;
        out.reserve((size * 4 + 2) / 3);
        size_t i = 0;
        for (; i + 3 <= size; i += 3)
        {
            uint32_t v = data[i] << 16 | data[i + 1] << 8 | data[i + 2];
            out += alphabet[v >> 18 & 63];
            out += alphabet[v >> 12 & 63];
            out += alphabet[v >> 6 & 63];
            out += alphabet[v & 63];
        }
        if (size - i == 1)
        {
            uint32_t v = data[i] << 16;
            out += alphabet[v >> 18 & 63];
            out += alphabet[v >> 12 & 63];
        }
        else if (size - i == 2)
        {
            uint32_t v = data[i] << 16 | data[i + 1] << 8;
            out += alphabet[v >> 18 & 63];
            out += alphabet[v >> 12 & 63];
            out += alphabet[v >> 6 & 63];
        }
        return out;
    }

    auto decode(std::string_view text) -> std::optional<Bytes>
    {
        if (text.size() % 4 == 1)
        {
            return std::nullopt;
        }
        Bytes    out;
        uint32_t acc  = 0;
        int      bits = 0;
        out.reserve(text.size() * 3 / 4);
        for (char c : text)
        {
            int v = value(c);
            if (v < 0)
            {
                return std::nullopt;
            }
            acc = acc << 6 | static_cast<uint32_t>(v);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back(static_cast<uint8_t>(acc >> bits));
                acc &= (1u << bits) - 1;
            }
        }
        if (acc != 0) // non-canonical leftover bits
        {
            return std::nullopt;
        }
        return out;
    }
} // namespace base64url

// ---------------------------------------------------------------------------------------------------------------
// RFC 3339

namespace rfc3339
{
    namespace
    {
        // Howard Hinnant's days_from_civil.
        auto daysFromCivil(int64_t y, unsigned m, unsigned d) -> int64_t
        {
            y -= m <= 2;
            const int64_t  era = (y >= 0 ? y : y - 399) / 400;
            const unsigned yoe = static_cast<unsigned>(y - era * 400);
            const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
            const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            return era * 146097 + static_cast<int64_t>(doe) - 719468;
        }

        void civilFromDays(int64_t z, int64_t& y, unsigned& m, unsigned& d)
        {
            z += 719468;
            const int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
            const unsigned doe = static_cast<unsigned>(z - era * 146097);
            const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            const unsigned mp  = (5 * doy + 2) / 153;
            d                  = doy - (153 * mp + 2) / 5 + 1;
            m                  = mp < 10 ? mp + 3 : mp - 9;
            y                  = static_cast<int64_t>(yoe) + era * 400 + (m <= 2);
        }

        auto digits(std::string_view s, size_t pos, size_t count, int& out) -> bool
        {
            if (pos + count > s.size())
            {
                return false;
            }
            out = 0;
            for (size_t i = pos; i < pos + count; ++i)
            {
                if (s[i] < '0' || s[i] > '9')
                {
                    return false;
                }
                out = out * 10 + (s[i] - '0');
            }
            return true;
        }
    } // namespace

    auto format(int64_t unixSeconds) -> std::string
    {
        int64_t  days = unixSeconds >= 0 ? unixSeconds / 86400 : (unixSeconds - 86399) / 86400;
        int64_t  secs = unixSeconds - days * 86400;
        int64_t  y    = 0;
        unsigned m = 0, d = 0;
        civilFromDays(days, y, m, d);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02lld:%02lld:%02lldZ", static_cast<long long>(y), m, d,
                      static_cast<long long>(secs / 3600), static_cast<long long>(secs / 60 % 60), static_cast<long long>(secs % 60));
        return buf;
    }

    auto parse(std::string_view s) -> std::optional<int64_t>
    {
        int y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
        if (!digits(s, 0, 4, y) || s.size() < 20 || s[4] != '-' || !digits(s, 5, 2, mo) || s[7] != '-' || !digits(s, 8, 2, d) ||
            (s[10] != 'T' && s[10] != 't') || !digits(s, 11, 2, h) || s[13] != ':' || !digits(s, 14, 2, mi) || s[16] != ':' ||
            !digits(s, 17, 2, sec))
        {
            return std::nullopt;
        }
        size_t pos = 19;
        if (s[pos] == '.')
        {
            size_t start = ++pos;
            while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
            {
                ++pos;
            }
            if (pos == start || pos - start > 9)
            {
                return std::nullopt;
            }
        }
        int offset = 0;
        if (pos < s.size() && (s[pos] == 'Z' || s[pos] == 'z'))
        {
            ++pos;
        }
        else if (pos < s.size() && (s[pos] == '+' || s[pos] == '-'))
        {
            int oh = 0, om = 0;
            if (!digits(s, pos + 1, 2, oh) || pos + 3 >= s.size() || s[pos + 3] != ':' || !digits(s, pos + 4, 2, om) || oh > 23 || om > 59)
            {
                return std::nullopt;
            }
            offset = (oh * 60 + om) * 60 * (s[pos] == '-' ? -1 : 1);
            pos += 6;
        }
        else
        {
            return std::nullopt;
        }
        if (pos != s.size())
        {
            return std::nullopt;
        }

        static constexpr int monthDays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        bool                 leap        = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > monthDays[mo - 1] + (mo == 2 && leap) || h > 23 || mi > 59 || sec > 59)
        {
            return std::nullopt;
        }
        return daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offset;
    }
} // namespace rfc3339

// ---------------------------------------------------------------------------------------------------------------
// Keys

namespace
{
    constexpr std::string_view secretPrefix = "k4.secret.";
    constexpr std::string_view publicPrefix = "k4.public.";

    auto decodePaserk(std::string_view text, std::string_view prefix, size_t size) -> std::optional<Bytes>
    {
        if (text.substr(0, prefix.size()) != prefix)
        {
            return std::nullopt;
        }
        auto raw = base64url::decode(text.substr(prefix.size()));
        if (!raw || raw->size() != size)
        {
            return std::nullopt;
        }
        return raw;
    }
} // namespace

auto isValidKeyId(std::string_view kid) -> bool
{
    if (kid.empty() || kid.size() > 64)
    {
        return false;
    }
    for (char c : kid)
    {
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-';
        if (!ok)
        {
            return false;
        }
    }
    return true;
}

auto SigningKey::generate(std::string kid) -> std::optional<SigningKey>
{
    Key32 seed{};
    if (!randomBytes(seed.data(), seed.size()))
    {
        return std::nullopt;
    }
    auto key = fromSeed(std::move(kid), seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    return key;
}

auto SigningKey::fromSeed(std::string kid, const Key32& seed) -> std::optional<SigningKey>
{
    SigningKey key;
    if (!isValidKeyId(kid) || !publicFromSeed(seed, key.pub_))
    {
        return std::nullopt;
    }
    key.kid_  = std::move(kid);
    key.seed_ = seed;
    return key;
}

auto SigningKey::fromPaserk(std::string kid, std::string_view k4secret) -> std::optional<SigningKey>
{
    auto raw = decodePaserk(k4secret, secretPrefix, 64);
    if (!raw)
    {
        return std::nullopt;
    }
    Key32 seed{};
    std::memcpy(seed.data(), raw->data(), 32);
    auto key = fromSeed(std::move(kid), seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    bool match = key && CRYPTO_memcmp(key->pub_.data(), raw->data() + 32, 32) == 0;
    OPENSSL_cleanse(raw->data(), raw->size());
    return match ? key : std::nullopt;
}

auto SigningKey::paserkSecret() const -> std::string
{
    Bytes raw(seed_.begin(), seed_.end());
    raw.insert(raw.end(), pub_.begin(), pub_.end());
    auto text = std::string(secretPrefix) + base64url::encode(raw);
    OPENSSL_cleanse(raw.data(), raw.size());
    return text;
}

auto SigningKey::paserkPublic() const -> std::string
{
    return std::string(publicPrefix) + base64url::encode(pub_.data(), pub_.size());
}

auto decodePaserkPublic(std::string_view k4public) -> std::optional<Key32>
{
    auto raw = decodePaserk(k4public, publicPrefix, 32);
    if (!raw)
    {
        return std::nullopt;
    }
    Key32 key{};
    std::memcpy(key.data(), raw->data(), 32);
    return key;
}

auto SigningKey::serverId() const -> std::string
{
    return serverIdFromPublicKey(pub_);
}

auto serverIdFromPublicKey(const Key32& identityPublicKey) -> std::string
{
    static constexpr char domain[] = "xitoken server id"; // hashed with its terminating NUL
    std::string           input(domain, sizeof(domain));
    input.append(reinterpret_cast<const char*>(identityPublicKey.data()), identityPublicKey.size());
    uint8_t      hash[32];
    unsigned int len = 0;
    if (EVP_Digest(input.data(), input.size(), hash, &len, EVP_sha256(), nullptr) != 1 || len != sizeof(hash))
    {
        throw std::runtime_error("xitoken: SHA-256 failed");
    }
    return "xi1." + base64url::encode(hash, 16);
}

auto isValidServerId(std::string_view id) -> bool
{
    if (id.size() != 26 || id.substr(0, 4) != "xi1.")
    {
        return false;
    }
    auto body = base64url::decode(id.substr(4));
    return body && body->size() == 16;
}

auto KeySet::create(const SigningKey& identity, const std::optional<std::string>& name, const std::vector<SigningKey>& signingKeys,
                    int64_t issuedAt, std::optional<int64_t> expires) -> std::string
{
    json keys = json::array();
    for (const auto& key : signingKeys)
    {
        keys.push_back({ { "kid", key.keyId() }, { "public", key.paserkPublic() } });
    }
    json payload = { { "typ", type }, { "iss", identity.serverId() }, { "iat", rfc3339::format(issuedAt) }, { "keys", keys } };
    if (name)
    {
        payload["name"] = *name;
    }
    if (expires)
    {
        payload["exp"] = rfc3339::format(*expires);
    }
    json footer = { { "idk", identity.paserkPublic() } };
    return paseto::sign(identity, payload.dump(), footer.dump());
}

auto KeySet::open(std::string_view token, int64_t now, std::string* error) -> std::optional<KeySet>
{
    auto fail = [&](std::string message) -> std::optional<KeySet>
    {
        if (error)
        {
            *error = std::move(message);
        }
        return std::nullopt;
    };
    while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back())))
    {
        token.remove_suffix(1);
    }
    while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front())))
    {
        token.remove_prefix(1);
    }

    auto parts  = paseto::parse(token);
    auto footer = parts ? parseObject(parts->footer) : std::nullopt;
    auto idk    = footer ? getString(*footer, "idk") : std::nullopt;
    auto pub    = idk ? decodePaserkPublic(*idk) : std::nullopt;
    if (!pub)
    {
        return fail("not a signed key set");
    }
    auto verified = paseto::verify(token, *pub);
    if (!verified)
    {
        return fail("key set signature is not valid");
    }
    auto payload = parseObject(verified->payload);
    if (!payload)
    {
        return fail("key set payload is not a JSON object");
    }

    KeySet set;
    set.serverId = serverIdFromPublicKey(*pub);
    if (getString(*payload, "typ") != std::optional<std::string>(type))
    {
        return fail("not an xi.keyset/1 document");
    }
    if (getString(*payload, "iss") != set.serverId)
    {
        return fail("key set iss does not match its identity key");
    }
    auto iat = getString(*payload, "iat");
    auto iatTime = iat ? rfc3339::parse(*iat) : std::nullopt;
    if (!iatTime)
    {
        return fail("key set has no valid iat");
    }
    set.issuedAt = *iatTime;
    if (payload->contains("exp"))
    {
        auto exp     = getString(*payload, "exp");
        auto expTime = exp ? rfc3339::parse(*exp) : std::nullopt;
        if (!expTime)
        {
            return fail("key set exp is not valid");
        }
        if (now >= *expTime)
        {
            return fail("key set has expired");
        }
        set.expires = expTime;
    }
    if (payload->contains("name"))
    {
        set.name = getString(*payload, "name");
        if (!set.name)
        {
            return fail("key set name must be a string");
        }
    }
    auto keys = payload->find("keys");
    if (keys == payload->end() || !keys->is_array())
    {
        return fail("key set has no keys array");
    }
    for (const auto& entry : *keys)
    {
        auto kid = entry.is_object() ? getString(entry, "kid") : std::nullopt;
        auto pk  = entry.is_object() ? getString(entry, "public") : std::nullopt;
        if (!kid || !pk)
        {
            return fail("key entries need kid and public");
        }
        if (!isValidKeyId(*kid))
        {
            return fail("invalid key id '" + *kid + "'");
        }
        for (const auto& existing : set.keys)
        {
            if (existing.kid == *kid)
            {
                return fail("duplicate key id '" + *kid + "'");
            }
        }
        auto key = decodePaserkPublic(*pk);
        if (!key)
        {
            return fail("key '" + *kid + "' is not a k4.public key");
        }
        set.keys.push_back(TrustedKey{ set.serverId, *kid, *key });
    }
    return set;
}

auto KeySetResolver::find(const std::string& issuer, const std::string& kid) const -> std::optional<TrustedKey>
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto                        it = sets_.find(issuer);
    if (it == sets_.end())
    {
        return std::nullopt;
    }
    for (const auto& key : it->second.keys)
    {
        if (key.kid == kid)
        {
            return key;
        }
    }
    return std::nullopt;
}

auto KeySetResolver::trust(std::string_view token, const std::string& expectedServerId, int64_t now, std::string* error) -> bool
{
    auto set = KeySet::open(token, now < 0 ? systemNow() : now, error);
    if (!set)
    {
        return false;
    }
    if (set->serverId != expectedServerId)
    {
        if (error)
        {
            *error = "key set belongs to " + set->serverId + ", not " + expectedServerId;
        }
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto                        it = sets_.find(set->serverId);
    if (it != sets_.end() && it->second.issuedAt > set->issuedAt)
    {
        if (error)
        {
            *error = "key set for " + set->serverId + " is older than the one loaded";
        }
        return false;
    }
    sets_[set->serverId] = std::move(*set);
    return true;
}

auto KeySetResolver::trustFile(const std::string& path, const std::string& expectedServerId, int64_t now, std::string* error) -> bool
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        if (error)
        {
            *error = "cannot read " + path;
        }
        return false;
    }
    std::stringstream ss;
    ss << file.rdbuf();
    return trust(ss.str(), expectedServerId, now, error);
}

auto KeySetResolver::size() const -> size_t
{
    std::lock_guard<std::mutex> lock(mutex_);
    return sets_.size();
}

// ---------------------------------------------------------------------------------------------------------------
// PASETO v4.public

namespace paseto
{
    auto pae(const std::vector<std::string_view>& pieces) -> std::string
    {
        auto le64 = [](std::string& out, uint64_t n)
        {
            n &= 0x7FFFFFFFFFFFFFFFull;
            for (int i = 0; i < 8; ++i)
            {
                out += static_cast<char>(n >> (8 * i) & 0xFF);
            }
        };
        std::string out;
        le64(out, pieces.size());
        for (auto piece : pieces)
        {
            le64(out, piece.size());
            out.append(piece);
        }
        return out;
    }

    auto sign(const SigningKey& key, std::string_view payload, std::string_view footer, std::string_view implicitAssertion) -> std::string
    {
        std::string m2 = pae({ header, payload, footer, implicitAssertion });

        Pkey  pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, key.seed().data(), key.seed().size()));
        MdCtx ctx(EVP_MD_CTX_new());
        uint8_t sig[signatureSize];
        size_t  sigLen = sizeof(sig);
        if (!pkey || !ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1 ||
            EVP_DigestSign(ctx.get(), sig, &sigLen, bytesOf(m2), m2.size()) != 1 || sigLen != signatureSize)
        {
            throw std::runtime_error("xitoken: Ed25519 signing failed");
        }

        std::string body(payload);
        body.append(reinterpret_cast<const char*>(sig), sigLen);
        std::string token = std::string(header) + base64url::encode(body);
        if (!footer.empty())
        {
            token += '.';
            token += base64url::encode(footer);
        }
        return token;
    }

    auto parse(std::string_view token) -> std::optional<Parts>
    {
        if (token.size() > maxTokenSize || token.substr(0, header.size()) != header)
        {
            return std::nullopt;
        }
        std::string_view rest     = token.substr(header.size());
        size_t           dot      = rest.find('.');
        std::string_view bodyText = rest.substr(0, dot);

        Parts parts;
        if (dot != std::string_view::npos)
        {
            std::string_view footerText = rest.substr(dot + 1);
            auto             footer     = footerText.empty() || footerText.find('.') != std::string_view::npos
                                              ? std::nullopt
                                              : base64url::decode(footerText);
            if (!footer)
            {
                return std::nullopt;
            }
            parts.footer.assign(footer->begin(), footer->end());
        }
        auto body = base64url::decode(bodyText);
        if (!body || body->size() < signatureSize)
        {
            return std::nullopt;
        }
        parts.payload.assign(body->begin(), body->end() - signatureSize);
        parts.signature.assign(body->end() - signatureSize, body->end());
        return parts;
    }

    auto verify(std::string_view token, const Key32& publicKey, std::string_view implicitAssertion) -> std::optional<Parts>
    {
        auto parts = parse(token);
        if (!parts)
        {
            return std::nullopt;
        }
        std::string m2 = pae({ header, parts->payload, parts->footer, implicitAssertion });

        Pkey  pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.data(), publicKey.size()));
        MdCtx ctx(EVP_MD_CTX_new());
        if (!pkey || !ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1 ||
            EVP_DigestVerify(ctx.get(), bytesOf(parts->signature), parts->signature.size(), bytesOf(m2), m2.size()) != 1)
        {
            return std::nullopt;
        }
        return parts;
    }
} // namespace paseto

// ---------------------------------------------------------------------------------------------------------------
// Tokens

auto toString(Error error) -> const char*
{
    switch (error)
    {
        case Error::None:
            return "ok";
        case Error::Malformed:
            return "malformed";
        case Error::UnknownKey:
            return "unknown_key";
        case Error::BadSignature:
            return "bad_signature";
        case Error::BadClaims:
            return "bad_claims";
        case Error::WrongIssuer:
            return "wrong_issuer";
        case Error::WrongAudience:
            return "wrong_audience";
        case Error::WrongType:
            return "wrong_type";
        case Error::NotYetValid:
            return "not_yet_valid";
        case Error::Expired:
            return "expired";
        case Error::LifetimeTooLong:
            return "lifetime_too_long";
        case Error::Replayed:
            return "replayed";
    }
    return "unknown";
}

auto systemNow() -> int64_t
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

MemoryReplayGuard::MemoryReplayGuard(std::function<int64_t()> now)
: now_(now ? std::move(now) : systemNow)
{
}

auto MemoryReplayGuard::tryConsume(const std::string& issuer, const std::string& jti, int64_t keepUntil) -> bool
{
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t                     now = now_();
    if (seen_.size() > 1024)
    {
        for (auto it = seen_.begin(); it != seen_.end();)
        {
            it = it->second <= now ? seen_.erase(it) : std::next(it);
        }
    }
    std::string key = issuer + '\n' + jti;
    auto        it  = seen_.find(key);
    if (it != seen_.end() && it->second > now)
    {
        return false;
    }
    seen_[key] = keepUntil;
    return true;
}

Verifier::Verifier(const KeyResolver& keys, VerifierOptions options)
: keys_(keys)
, options_(std::move(options))
{
    if (!options_.now)
    {
        options_.now = systemNow;
    }
}

auto Verifier::verify(std::string_view token, std::string_view expectedType) const -> VerifyResult
{
    auto fail = [](Error e)
    {
        return VerifyResult{ e, std::nullopt };
    };

    // 1-3: parse, find key, check signature
    auto parts = paseto::parse(token);
    if (!parts || parts->footer.empty() || parts->footer.size() > maxFooterSize)
    {
        return fail(Error::Malformed);
    }
    auto footer    = parseObject(parts->footer);
    auto keyIssuer = footer ? getString(*footer, "iss") : std::nullopt;
    auto kid       = footer ? getString(*footer, "kid") : std::nullopt;
    if (!keyIssuer || !kid)
    {
        return fail(Error::Malformed);
    }
    auto key = keys_.find(*keyIssuer, *kid);
    if (!key)
    {
        return fail(Error::UnknownKey);
    }
    auto verified = paseto::verify(token, key->publicKey);
    if (!verified)
    {
        return fail(Error::BadSignature);
    }

    // 4: claims
    auto claims = parseObject(verified->payload);
    if (!claims)
    {
        return fail(Error::BadClaims);
    }
    auto nonEmpty = [&](const char* name)
    {
        auto v = getString(*claims, name);
        return v && !v->empty() ? v : std::nullopt;
    };
    auto time = [&](const char* name)
    {
        auto v = getString(*claims, name);
        return v ? rfc3339::parse(*v) : std::nullopt;
    };
    auto iss = nonEmpty("iss");
    auto aud = nonEmpty("aud");
    auto sub = nonEmpty("sub");
    auto typ = nonEmpty("typ");
    auto jti = nonEmpty("jti");
    auto iat = time("iat");
    auto exp = time("exp");
    if (!iss || !aud || !sub || !typ || !jti || jti->size() < 22 || !iat || !exp)
    {
        return fail(Error::BadClaims);
    }
    std::optional<int64_t> nbf;
    if (claims->contains("nbf"))
    {
        nbf = time("nbf");
        if (!nbf)
        {
            return fail(Error::BadClaims);
        }
    }

    // 5-7: who and what
    if (*iss != key->issuer)
    {
        return fail(Error::WrongIssuer);
    }
    if (*aud != options_.audience)
    {
        return fail(Error::WrongAudience);
    }
    if (*typ != expectedType)
    {
        return fail(Error::WrongType);
    }

    // 8: time
    int64_t now  = options_.now();
    int64_t skew = options_.clockSkew;
    if (now + skew < *iat || (nbf && now + skew < *nbf))
    {
        return fail(Error::NotYetValid);
    }
    if (now - skew >= *exp)
    {
        return fail(Error::Expired);
    }
    if (*exp - *iat > options_.maxLifetime)
    {
        return fail(Error::LifetimeTooLong);
    }

    // 9: single use
    if (options_.replayGuard && !options_.replayGuard->tryConsume(*iss, *jti, *exp + skew))
    {
        return fail(Error::Replayed);
    }

    return VerifyResult{ Error::None, Token{ *iss, *aud, *sub, *typ, *jti, *kid, *iat, *exp, std::move(*claims) } };
}

Issuer::Issuer(std::string serverId, SigningKey key)
: issuer_(std::move(serverId))
, key_(std::move(key))
{
    if (!isValidServerId(issuer_))
    {
        throw std::invalid_argument("xitoken: '" + issuer_ + "' is not a server id");
    }
}

auto Issuer::issue(const std::string& type, const std::string& audience, const std::string& subject, int64_t lifetimeSeconds,
                   const nlohmann::json& claims, int64_t now) const -> std::string
{
    if (now < 0)
    {
        now = systemNow();
    }
    uint8_t jti[16];
    if (!randomBytes(jti, sizeof(jti)))
    {
        throw std::runtime_error("xitoken: RAND_bytes failed");
    }
    json payload = {
        { "iss", issuer_ },
        { "aud", audience },
        { "sub", subject },
        { "typ", type },
        { "jti", base64url::encode(jti, sizeof(jti)) },
        { "iat", rfc3339::format(now) },
        { "exp", rfc3339::format(now + lifetimeSeconds) },
    };
    if (!claims.is_object())
    {
        throw std::invalid_argument("xitoken: claims must be a JSON object");
    }
    for (const auto& [name, value] : claims.items())
    {
        if (payload.contains(name) || name == "nbf")
        {
            throw std::invalid_argument("xitoken: claim '" + name + "' is set by the issuer");
        }
        payload[name] = value;
    }
    json footer = { { "iss", issuer_ }, { "kid", key_.keyId() } };
    return paseto::sign(key_, payload.dump(), footer.dump());
}

// ---------------------------------------------------------------------------------------------------------------
// xi.world-entry/1

auto WorldEntry::toClaims() const -> nlohmann::json
{
    if (!parseIPv4(clientIp))
    {
        throw std::invalid_argument("xitoken: client ip must be a dotted IPv4 address");
    }
    if (clientVersion.size() > 16)
    {
        throw std::invalid_argument("xitoken: client version is at most 16 characters");
    }
    json character = { { "id", charId } };
    if (charName)
    {
        character["name"] = *charName;
    }
    return {
        { "char", character },
        { "client", { { "ip", clientIp }, { "version", clientVersion }, { "expansions", clientExpansions } } },
        { "skey", base64url::encode(sessionKey.data(), sessionKey.size()) },
    };
}

auto WorldEntry::fromClaims(const nlohmann::json& claims) -> std::optional<WorldEntry>
{
    auto character = claims.find("char");
    auto client    = claims.find("client");
    if (character == claims.end() || !character->is_object() || client == claims.end() || !client->is_object())
    {
        return std::nullopt;
    }
    WorldEntry entry;
    auto       id         = getUInt32(*character, "id");
    auto       expansions = getUInt32(*client, "expansions");
    auto       ip         = getString(*client, "ip");
    auto       version    = getString(*client, "version");
    auto       skeyText   = getString(claims, "skey");
    auto       skey       = skeyText ? base64url::decode(*skeyText) : std::nullopt;
    if (!id || !expansions || !ip || !parseIPv4(*ip) || !version || version->size() > 16 || !skey || skey->size() != entry.sessionKey.size())
    {
        return std::nullopt;
    }
    if (character->contains("name"))
    {
        auto name = getString(*character, "name");
        if (!name)
        {
            return std::nullopt;
        }
        entry.charName = *name;
    }
    entry.charId           = *id;
    entry.clientIp         = *ip;
    entry.clientVersion    = *version;
    entry.clientExpansions = *expansions;
    std::memcpy(entry.sessionKey.data(), skey->data(), entry.sessionKey.size());
    OPENSSL_cleanse(skey->data(), skey->size());
    return entry;
}

auto WorldEntry::clientAddrLsb() const -> uint32_t
{
    auto octets = parseIPv4(clientIp);
    if (!octets)
    {
        return 0;
    }
    return static_cast<uint32_t>((*octets)[0]) | static_cast<uint32_t>((*octets)[1]) << 8 | static_cast<uint32_t>((*octets)[2]) << 16 |
           static_cast<uint32_t>((*octets)[3]) << 24;
}

} // namespace xitoken
