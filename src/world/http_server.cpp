/*
===========================================================================

  Copyright (c) 2022 LandSandBoat Dev Teams

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

#include "http_server.h"

#include "common/database.h"
#include "common/logging.h"
#include "common/settings.h"
#include "common/utils.h"
#include "common/cert_helpers.h"
#include "common/xi.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <unordered_set>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace
{
    // "sha256:" + base64url of the SHA-256 of the certificate's DER encoding: the pin a client checks against a
    // self-signed certificate (ext/xitoken/SPEC.md "Transport").
    auto certificatePin(const std::string& certFile) -> std::string
    {
        FILE* file = fopen(certFile.c_str(), "r");
        if (!file)
        {
            return {};
        }
        X509* cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
        fclose(file);
        if (!cert)
        {
            return {};
        }
        unsigned char* der    = nullptr;
        const int      length = i2d_X509(cert, &der);
        X509_free(cert);
        if (length <= 0)
        {
            return {};
        }
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int  hashLength = 0;
        EVP_Digest(der, static_cast<size_t>(length), hash, &hashLength, EVP_sha256(), nullptr);
        OPENSSL_free(der);

        static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string           out        = "sha256:";
        for (unsigned int i = 0; i < hashLength; i += 3)
        {
            const uint32 v = hash[i] << 16 | (i + 1 < hashLength ? hash[i + 1] << 8 : 0) | (i + 2 < hashLength ? hash[i + 2] : 0);
            out += alphabet[v >> 18 & 63];
            out += alphabet[v >> 12 & 63];
            if (i + 1 < hashLength)
            {
                out += alphabet[v >> 6 & 63];
            }
            if (i + 2 < hashLength)
            {
                out += alphabet[v & 63];
            }
        }
        return out;
    }
} // namespace

HTTPServer::HTTPServer(Scheduler& scheduler, std::function<void(httplib::Server&)> registerRoutes)
: scheduler_(scheduler)
, apiDataCache_(APIDataCache{})
{
    // NOTE: Everything registered in here happens off the main thread, so lock any global resources
    //     : you might be using.

    LockingUpdate();

    auto host = settings::get<std::string>("network.HTTP_HOST");
    auto port = settings::get<uint16>("network.HTTP_PORT");

    // TLS: the certificate and key named by network.HTTP_TLS_CERT / HTTP_TLS_KEY, self-signed on first start when
    // neither exists. Clients that cannot validate it pin it instead; the pin is logged here.
    if (settings::get<bool>("network.HTTP_TLS"))
    {
        auto cert = settings::get<std::string>("network.HTTP_TLS_CERT");
        auto key  = settings::get<std::string>("network.HTTP_TLS_KEY");
        if (cert == "world.cert" && key == "world.key")
        {
            certificateHelpers::generateSelfSignedCert("world");
        }
        httpServer_ = std::make_unique<httplib::SSLServer>(cert.c_str(), key.c_str());
        if (!httpServer_->is_valid())
        {
            ShowErrorFmt("HTTP Server: cannot load TLS certificate {} / key {}", cert, key);
        }
        ShowInfoFmt("Starting HTTPS Server on https://{}:{}/api (certificate pin {})", host, port, certificatePin(cert));
    }
    else
    {
        httpServer_ = std::make_unique<httplib::Server>();
        ShowInfoFmt("Starting HTTP Server on http://{}:{}/api", host, port);
    }

    scheduler_.postToWorkerThread(
        [this, host, port, registerRoutes = std::move(registerRoutes)]()
        {
            httpServer_->Get(
                "/api",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    res.set_content("Hello LSB API", "text/plain");
                });

            httpServer_->Get(
                "/api/sessions",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    LockingUpdate();
                    apiDataCache_.read([&](const auto& apiDataCache)
                                       {
                                           json j = apiDataCache.activeSessionCount;
                                           res.set_content(j.dump(), "application/json");
                                       });
                });

            httpServer_->Get(
                "/api/ips",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    LockingUpdate();
                    apiDataCache_.read(
                        [&](const auto& apiDataCache)
                        {
                            json j = apiDataCache.activeUniqueIPCount;
                            res.set_content(j.dump(), "application/json");
                        });
                });

            httpServer_->Get(
                "/api/zones",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    LockingUpdate();
                    apiDataCache_.read(
                        [&](const auto& apiDataCache)
                        {
                            json j = apiDataCache.zonePlayerCounts;
                            res.set_content(j.dump(), "application/json");
                        });
                });

            httpServer_->Get(
                R"(/api/zones/(\d+))",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    auto   maybeZoneId = req.matches[1].str();
                    uint16 zoneId      = std::strtol(maybeZoneId.c_str(), nullptr, 10);
                    if (zoneId && zoneId < MAX_ZONEID)
                    {
                        LockingUpdate();
                        apiDataCache_.read(
                            [&](const auto& apiDataCache)
                            {
                                json j = apiDataCache.zonePlayerCounts[zoneId];
                                res.set_content(j.dump(), "application/json");
                            });
                    }
                    else
                    {
                        res.status = 404;
                    }
                });

            httpServer_->Get(
                "/api/settings",
                [&](const httplib::Request& req, httplib::Response& res)
                {
                    // TODO: Cache these
                    json j{};

                    // Filter out settings we don't want to expose
                    std::unordered_set<std::string> textToOmit{
                        "logging.",
                        "network.",
                        "password", // Just in case
                    };

                    settings::visit(
                        [&](const auto& key, const auto& variant)
                        {
                            // Keys are stored verbatim (mixed case), and the omit list is lowercase,
                            // so match case-insensitively to still catch e.g. "...PASSWORD".
                            const auto lowerKey = to_lower(key);
                            for (const auto& text : textToOmit)
                            {
                                if (lowerKey.find(text) != std::string::npos)
                                {
                                    return;
                                }
                            }

                            variant.visit(
                                overload{
                                    [&](const bool& arg)
                                    {
                                        j[key] = arg;
                                    },
                                    [&](const double& arg)
                                    {
                                        j[key] = arg;
                                    },
                                    [&](const std::string& arg)
                                    {
                                        // JSON can't handle non-ASCII characters, so strip them out
                                        j[key] = utils::toASCII(arg, '?');
                                    },
                                });
                        });

                    res.set_content(j.dump(), "application/json");
                });

            if (registerRoutes)
            {
                registerRoutes(*httpServer_);
            }

            httpServer_->set_error_handler(
                [](const httplib::Request& /*req*/, httplib::Response& res) -> httplib::Server::HandlerResponse
                {
                    // Routes that answer an error with their own body (e.g. the federation gateway's JSON) keep it.
                    if (!res.body.empty())
                    {
                        return httplib::Server::HandlerResponse::Unhandled;
                    }

                    auto str = fmt::format("<p>Error Status: <span style='color:red;'>{} ({})</span></p>",
                                           res.status,
                                           httplib::status_message(res.status));

                    for (const auto& [key, val] : res.headers)
                    {
                        str += fmt::format("<p>{}: {}</p>", key, val);
                    }

                    res.set_content(str, "text/html");
                    return httplib::Server::HandlerResponse::Handled;
                });

            httpServer_->set_logger(
                [](const httplib::Request& req, const httplib::Response& res)
                {
                    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
                    if (res.status >= 500)
                    {
                        ShowErrorFmt("Server Error: {} ({})", res.status, httplib::status_message(res.status));
                        return;
                    }
                    else if (res.status >= 400)
                    {
                        ShowErrorFmt("Client Error: {} ({})", res.status, httplib::status_message(res.status));
                        return;
                    }
                });

            httpServer_->listen(host, port); // blocks
        });
}

HTTPServer::~HTTPServer()
{
    httpServer_->stop();
}

void HTTPServer::LockingUpdate()
{
    auto now = timer::now();
    if (now < (lastUpdate_.load() + 60s))
    {
        return;
    }

    apiDataCache_.write(
        [&](auto& apiDataCache)
        {
            ShowInfoFmt("API data is stale. Updating...");

            // Total active sessions
            {
                auto rset = db::preparedStmt("SELECT COUNT(*) AS `count` FROM accounts_sessions");
                if (rset && rset->next())
                {
                    apiDataCache.activeSessionCount = rset->get<uint32>("count");
                }
            }

            // Total active unique IPs
            {
                auto rset = db::preparedStmt("SELECT COUNT(DISTINCT client_addr) AS `count` FROM accounts_sessions");
                if (rset && rset->next())
                {
                    apiDataCache.activeUniqueIPCount = rset->get<uint32>("count");
                }
            }

            // Chars per zone
            {
                auto rset = db::preparedStmt("SELECT chars.pos_zone, COUNT(*) AS `count` "
                                             "FROM chars "
                                             "INNER JOIN accounts_sessions "
                                             "ON chars.charid = accounts_sessions.charid "
                                             "GROUP BY pos_zone");
                if (rset && rset->rowsCount())
                {
                    while (rset->next())
                    {
                        auto zoneId = rset->get<uint16>("pos_zone");
                        auto count  = rset->get<uint32>("count");

                        apiDataCache.zonePlayerCounts[zoneId] = count;
                    }
                }
            }

            lastUpdate_.store(now);
        });
}
