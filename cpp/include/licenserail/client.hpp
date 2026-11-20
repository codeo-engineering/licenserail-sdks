// LicenseRail client for native apps and plugins (C++17). Needs only the public key; never ship an API key.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "licenserail/core.hpp"

namespace licenserail {

/// HTTP POST of a JSON body; returns {status code, response body}. Status 0 = network failure.
struct HttpResponse {
    int status = 0;
    std::string body;
};
using Transport = std::function<HttpResponse(const std::string& url, const std::string& json_body, int timeout_seconds)>;

struct Options {
    std::string server_url;
    std::string product;
    std::string public_key_pem;
    std::string app_version;
    std::string storage_dir;  // default: per-user folder
    bool refresh_on_startup = false;
    int timeout_seconds = 10;
    std::string machine_name;
    std::optional<Fingerprint> fingerprint;  // default: collected from the OS
    Transport transport;                     // default: libcurl (when built with LICENSERAIL_WITH_CURL)
};

struct ActivationResult {
    bool success = false;
    std::string error_code;
    std::string message;
};

struct CheckResult {
    Status status = Status::Missing;
    std::optional<Payload> license;
    bool valid() const { return status == Status::Valid; }
};

/// Hashed device fingerprint (Windows, macOS, Linux).
Fingerprint collect_fingerprint(const std::string& product);

class Client {
public:
    explicit Client(Options options);

    /// Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state.
    CheckResult check();
    CheckResult evaluate_local();
    ActivationResult activate(const std::string& license_key, const std::string& machine_name = "");
    ActivationResult deactivate();
    /// Fresh token now (floating: a heartbeat; call every lease/2 while running).
    bool refresh(const std::vector<std::string>& anomalies = {});

    const std::optional<Payload>& license() const { return license_; }
    const std::string& last_server_message() const { return last_server_message_; }

private:
    HttpResponse post(const std::string& path, const std::string& body);
    bool save_if_valid(const std::string& token);
    std::string read(const std::string& name) const;
    void write(const std::string& name, const std::string& value) const;
    void remove(const std::string& name) const;
    std::string encode_history(int64_t ms) const;
    std::optional<int64_t> decode_history(const std::string& value) const;
    const Fingerprint& fp();

    Options options_;
    std::string dir_;
    std::optional<Fingerprint> fp_;
    std::optional<Payload> license_;
    std::string last_server_message_;
};

}  // namespace licenserail
