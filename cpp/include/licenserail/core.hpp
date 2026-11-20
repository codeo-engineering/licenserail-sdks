// LicenseRail: offline license logic shared by every SDK (see the test vectors).
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace licenserail {

inline constexpr const char* kUnavailable = "none";

enum class Status { Valid, Missing, InvalidSignature, WrongProduct, WrongMachine, Expired, OfflineTooLong, ClockTampered, Unverified, Suspended };

const char* to_string(Status s);

/// Hashed device components.
struct Fingerprint {
    std::string machine_id, disk_id, host_name, board_id;
    std::string os;  // empty = not reported
    /// Whether `presented` is the device this (registered) fingerprint was issued for.
    bool matches(const Fingerprint& presented) const;
};

/// The signed license content. `json` is the raw payload (metadata and future fields).
struct Payload {
    std::string json;
    std::string license_key, product, customer, kind;
    std::optional<int64_t> expires_at_ms;
    int64_t issued_at_ms = 0, refresh_after_ms = 0, offline_until_ms = 0;
    Fingerprint fingerprint;
    bool suspended = false, test = false, floating = false;
    std::vector<std::string> entitlements;
    bool has_feature(const std::string& code) const;
};

/// Verifies ECDSA P-256 / SHA-256 (IEEE P1363 r||s) over the ASCII encoded body with a SubjectPublicKeyInfo PEM.
std::optional<Payload> verify_token(const std::string& token, const std::string& public_key_pem);

/// hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw)))); empty gives "none".
/// vendor is the organization's slug (fixed for life).
/// Uppercasing covers ASCII, Latin-1 and Latin Extended-A, like the other SDKs for typical host names.
std::string hash_component(const std::string& vendor, const std::string& product, const std::string& part, const std::optional<std::string>& raw);

/// The offline check. Times are Unix milliseconds; last_seen empty = run history missing.
Status evaluate(const std::optional<Payload>& payload, const std::string& product, const Fingerprint& machine, int64_t now_ms,
                std::optional<int64_t> last_seen_ms);

/// ISO 8601 with offset → Unix milliseconds.
std::optional<int64_t> parse_time(const std::string& iso);

std::string sha256_hex(const std::string& data);
std::string hmac_sha256_hex_upper(const std::string& key_material, const std::string& data);

bool is_revoking_code(const std::string& code);

}  // namespace licenserail
