#include "licenserail/core.hpp"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <nlohmann/json.hpp>

namespace licenserail {

const char* to_string(Status s) {
    switch (s) {
        case Status::Valid: return "Valid";
        case Status::Missing: return "Missing";
        case Status::InvalidSignature: return "InvalidSignature";
        case Status::WrongProduct: return "WrongProduct";
        case Status::WrongMachine: return "WrongMachine";
        case Status::Expired: return "Expired";
        case Status::OfflineTooLong: return "OfflineTooLong";
        case Status::ClockTampered: return "ClockTampered";
        case Status::Unverified: return "Unverified";
        case Status::Suspended: return "Suspended";
    }
    return "Unknown";
}

bool is_revoking_code(const std::string& c) {
    return c == "license_not_found" || c == "license_suspended" || c == "license_expired" || c == "activation_revoked" ||
           c == "wrong_machine" || c == "invalid_token" || c == "license_revoked";
}

static bool available(const std::string& v) { return !v.empty() && v != kUnavailable; }
static bool same(const std::string& a, const std::string& b) { return available(a) && a == b; }

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool Fingerprint::matches(const Fingerprint& p) const {
    if (!os.empty() && !p.os.empty() && lower(os) != lower(p.os)) return false;
    int n = (same(machine_id, p.machine_id) ? 1 : 0) + (same(disk_id, p.disk_id) ? 1 : 0) + (same(host_name, p.host_name) ? 1 : 0);
    return available(board_id) ? same(board_id, p.board_id) && n >= 1 : n >= 2;
}

bool Payload::has_feature(const std::string& code) const {
    return std::find(entitlements.begin(), entitlements.end(), code) != entitlements.end();
}

static std::optional<std::string> b64url(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (in.size() % 4 == 1) return std::nullopt;
    std::string out;
    int val = 0, bits = -8;
    for (char c : in) {
        auto pos = chars.find(c);
        if (pos == std::string::npos) return std::nullopt;
        val = (val << 6) + static_cast<int>(pos);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

static std::string der_int(std::string x) {
    size_t i = 0;
    while (i + 1 < x.size() && x[i] == 0) i++;
    x = x.substr(i);
    if (static_cast<unsigned char>(x[0]) & 0x80) x.insert(x.begin(), '\0');
    return std::string("\x02", 1) + static_cast<char>(x.size()) + x;
}

std::string sha256_hex(const std::string& data) {
    unsigned char out[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, 0);
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (unsigned char b : out) { s += hex[b >> 4]; s += hex[b & 15]; }
    return s;
}

std::string hmac_sha256_hex_upper(const std::string& key_material, const std::string& data) {
    unsigned char key[32], out[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(key_material.data()), key_material.size(), key, 0);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, reinterpret_cast<const unsigned char*>(data.data()), data.size(), out);
    static const char* hex = "0123456789ABCDEF";
    std::string s;
    for (unsigned char b : out) { s += hex[b >> 4]; s += hex[b & 15]; }
    return s;
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

std::optional<int64_t> parse_time(const std::string& s) {
    int y, mo, d, h, mi, se;
    if (s.size() < 19 || std::sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) != 6) return std::nullopt;
    size_t i = 19;
    int64_t ms = 0;
    if (i < s.size() && s[i] == '.') {
        int digits = 0;
        for (i++; i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])); i++)
            if (digits < 3) { ms = ms * 10 + (s[i] - '0'); digits++; }
        while (digits++ < 3) ms *= 10;
    }
    int64_t offset = 0;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        int oh = 0, om = 0;
        std::sscanf(s.c_str() + i + 1, "%2d:%2d", &oh, &om);
        offset = (s[i] == '+' ? 1 : -1) * (oh * 3600 + om * 60);
    }
    int64_t secs = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 + h * 3600 + mi * 60 + se - offset;
    return secs * 1000 + ms;
}

std::optional<Payload> verify_token(const std::string& token, const std::string& pem) {
    std::string t = token;
    t.erase(0, t.find_first_not_of(" \t\r\n"));
    t.erase(t.find_last_not_of(" \t\r\n") + 1);
    auto dot = t.find('.');
    if (dot == std::string::npos || t.find('.', dot + 1) != std::string::npos) return std::nullopt;
    std::string encoded = t.substr(0, dot);
    auto sig = b64url(t.substr(dot + 1));
    auto body = b64url(encoded);
    if (!sig || !body || sig->size() != 64) return std::nullopt;

    std::string der = der_int(sig->substr(0, 32)) + der_int(sig->substr(32));
    der = std::string("\x30", 1) + static_cast<char>(der.size()) + der;
    unsigned char hash[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size(), hash, 0);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    std::string pem0 = pem + '\0';
    bool ok = mbedtls_pk_parse_public_key(&pk, reinterpret_cast<const unsigned char*>(pem0.data()), pem0.size()) == 0 &&
              mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, reinterpret_cast<const unsigned char*>(der.data()), der.size()) == 0;
    mbedtls_pk_free(&pk);
    if (!ok) return std::nullopt;

    auto j = nlohmann::json::parse(*body, nullptr, false);
    if (j.is_discarded() || !j.is_object() || !j.contains("fingerprint")) return std::nullopt;
    Payload p;
    p.json = *body;
    auto str = [&](const nlohmann::json& o, const char* k) { return o.contains(k) && o[k].is_string() ? o[k].get<std::string>() : std::string(); };
    p.license_key = str(j, "licenseKey");
    p.product = str(j, "product");
    p.customer = str(j, "customer");
    p.kind = str(j, "kind");
    if (j.contains("expiresAt") && j["expiresAt"].is_string()) p.expires_at_ms = parse_time(j["expiresAt"]);
    p.issued_at_ms = parse_time(str(j, "issuedAt")).value_or(0);
    p.refresh_after_ms = parse_time(str(j, "refreshAfter")).value_or(0);
    p.offline_until_ms = parse_time(str(j, "offlineUntil")).value_or(0);
    const auto& f = j["fingerprint"];
    p.fingerprint = {str(f, "machineId"), str(f, "diskId"), str(f, "hostName"), str(f, "boardId"), str(f, "os")};
    p.suspended = j.value("suspended", false);
    p.test = j.contains("test") && j["test"].is_boolean() && j["test"].get<bool>();
    p.floating = j.contains("floating") && j["floating"].is_boolean() && j["floating"].get<bool>();
    if (j.contains("entitlements") && j["entitlements"].is_array())
        for (const auto& e : j["entitlements"]) if (e.is_string()) p.entitlements.push_back(e.get<std::string>());
    return p;
}

// Uppercase for ASCII, Latin-1 Supplement and Latin Extended-A (matches .NET ToUpperInvariant for those ranges).
static std::string upper_utf8(const std::string& in) {
    std::string out;
    for (size_t i = 0; i < in.size();) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        uint32_t cp;
        int len;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c >> 5) == 6 && i + 1 < in.size()) { cp = ((c & 0x1F) << 6) | (in[i + 1] & 0x3F); len = 2; }
        else { out += in.substr(i, 1); i++; continue; }  // 3/4-byte sequences pass through unchanged
        if (cp >= 'a' && cp <= 'z') cp -= 32;
        else if (cp >= 0xE0 && cp <= 0xFE && cp != 0xF7) cp -= 32;
        else if (cp == 0xFF) cp = 0x178;
        else if (cp == 0x131) cp = 'I';
        else if (cp == 0x17F) cp = 'S';
        else if (cp >= 0x100 && cp <= 0x17F && cp != 0x138 && cp != 0x149) {
            bool oddLower = (cp >= 0x139 && cp <= 0x148) || (cp >= 0x179 && cp <= 0x17E);
            if (oddLower ? (cp % 2 == 0) : (cp % 2 == 1)) cp -= 1;
        }
        if (cp < 0x80) out += static_cast<char>(cp);
        else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
        i += len;
    }
    return out;
}

std::string hash_component(const std::string& vendor, const std::string& product, const std::string& part, const std::optional<std::string>& raw) {
    if (!raw) return kUnavailable;
    std::string t = *raw;
    t.erase(0, t.find_first_not_of(" \t\r\n"));
    if (t.empty()) return kUnavailable;
    t.erase(t.find_last_not_of(" \t\r\n") + 1);
    return sha256_hex(vendor + ":" + product + ":" + part + ":" + upper_utf8(t));
}

Status evaluate(const std::optional<Payload>& p, const std::string& product, const Fingerprint& machine, int64_t now, std::optional<int64_t> last_seen) {
    if (!p) return Status::InvalidSignature;
    if (lower(p->product) != lower(product)) return Status::WrongProduct;
    if (!p->fingerprint.matches(machine)) return Status::WrongMachine;
    if (p->suspended) return Status::Suspended;
    if (!last_seen) return Status::Unverified;
    if (now + 86400000LL < p->issued_at_ms || now + 600000LL < *last_seen) return Status::ClockTampered;
    if (p->expires_at_ms && now >= *p->expires_at_ms) return Status::Expired;
    if (now >= p->offline_until_ms) return Status::OfflineTooLong;
    return Status::Valid;
}

}  // namespace licenserail
