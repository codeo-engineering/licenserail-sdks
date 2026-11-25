#include "licenserail/client.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>

#ifdef LICENSERAIL_WITH_CURL
#include <curl/curl.h>
#endif

namespace fs = std::filesystem;
using nlohmann::json;

namespace licenserail {

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string run(const std::string& cmd) {
    std::string out;
#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) return out;
    std::array<char, 512> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) out += buf.data();
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return out;
}

static std::optional<std::string> find(const std::string& text, const std::string& pattern) {
    std::smatch m;
    if (std::regex_search(text, m, std::regex(pattern, std::regex::icase)) && m.size() > 1) return m[1].str();
    return std::nullopt;
}

static std::optional<std::string> read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    return s.empty() ? std::nullopt : std::optional<std::string>(s);
}

Fingerprint collect_fingerprint(const std::string& vendor, const std::string& product) {
    std::optional<std::string> machine, disk, host, board;
    std::string os;
#ifdef _WIN32
    os = "windows";
    machine = find(run("reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /reg:64"), "MachineGuid\\s+REG_SZ\\s+(\\S+)");
    if (auto v = find(run("cmd /c vol C:"), "([0-9A-F]{4}-[0-9A-F]{4})")) { std::string s = *v; s.erase(4, 1); disk = s; }
    board = find(run("powershell -NoProfile -Command \"(Get-CimInstance Win32_ComputerSystemProduct).UUID\""), "([0-9A-F-]{36})");
    if (const char* h = std::getenv("COMPUTERNAME")) host = h;
#elif defined(__APPLE__)
    os = "macos";
    std::string io = run("ioreg -rd1 -c IOPlatformExpertDevice");
    machine = find(io, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\"");
    board = find(io, "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\"");
    disk = find(run("diskutil info /"), "Volume UUID:\\s*([0-9A-F-]+)");
    host = find(run("scutil --get LocalHostName"), "(\\S+)");
#else
    os = "linux";
    machine = read_file("/etc/machine-id");
    if (!machine) machine = read_file("/var/lib/dbus/machine-id");
    board = read_file("/sys/class/dmi/id/product_uuid");
    host = read_file("/etc/hostname");
#endif
    if (board && std::regex_match(std::regex_replace(*board, std::regex("-"), ""), std::regex("[0Ff]*"))) board.reset();
    return {hash_component(vendor, product, "machine", machine), hash_component(vendor, product, "disk", disk), hash_component(vendor, product, "host", host),
            hash_component(vendor, product, "board", board), os};
}

#ifdef LICENSERAIL_WITH_CURL
static size_t collect(char* ptr, size_t size, size_t n, void* user) {
    static_cast<std::string*>(user)->append(ptr, size * n);
    return size * n;
}

static HttpResponse curl_post(const std::string& url, const std::string& body, int timeout) {
    HttpResponse r;
    CURL* c = curl_easy_init();
    if (!c) return r;
    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(timeout));
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
    if (curl_easy_perform(c) == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
        r.status = static_cast<int>(code);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(c);
    return r;
}
#endif

Client::Client(Options o) : options_(std::move(o)) {
    if (!options_.transport) {
#ifdef LICENSERAIL_WITH_CURL
        options_.transport = curl_post;
#else
        options_.transport = [](const std::string&, const std::string&, int) { return HttpResponse{}; };
#endif
    }
    dir_ = options_.storage_dir;
    if (dir_.empty()) {
#ifdef _WIN32
        const char* base = std::getenv("LOCALAPPDATA");
#else
        const char* base = std::getenv("HOME");
#endif
        dir_ = (fs::path(base ? base : ".") / ".licenserail" / options_.product).string();
    }
    fp_ = options_.fingerprint;
}

const Fingerprint& Client::fp() {
    if (!fp_) fp_ = collect_fingerprint(options_.vendor, options_.product);
    return *fp_;
}

static json fp_json(const Fingerprint& f) {
    json j = {{"machineId", f.machine_id}, {"diskId", f.disk_id}, {"hostName", f.host_name}, {"boardId", f.board_id}};
    if (!f.os.empty()) j["os"] = f.os;
    return j;
}

std::string Client::encode_history(int64_t ms) const {
    std::string s = std::to_string(ms);
    return s + "." + hmac_sha256_hex_upper(options_.vendor + ":run-history:" + options_.product + ":" + fp_->machine_id + ":" + fp_->board_id, s).substr(0, 32);
}

std::optional<int64_t> Client::decode_history(const std::string& v) const {
    auto dot = v.find('.');
    if (dot == std::string::npos) return std::nullopt;
    std::string ms = v.substr(0, dot);
    if (ms.empty() || ms.find_first_not_of("0123456789") != std::string::npos || ms.size() > 15) return std::nullopt;
    if (v.substr(dot + 1) != encode_history(std::stoll(ms)).substr(dot + 1)) return std::nullopt;
    return std::stoll(ms);
}

/// A string member of a response, whatever the server sent.
static std::string text(const json& j, const char* name, const char* fallback = "") {
    if (!j.is_object()) return fallback;
    auto v = j.find(name);
    return v != j.end() && v->is_string() ? v->get<std::string>() : fallback;
}

static bool is_ok(int status) { return status >= 200 && status < 300; }

CheckResult Client::evaluate_local() {
    std::string token = read("license.lic");
    if (token.empty()) { license_.reset(); return {Status::Missing, std::nullopt}; }
    fp();
    license_ = verify_token(token, options_.public_key_pem);
    auto last = decode_history(read("license.seen"));
    int64_t now = now_ms();
    Status s = evaluate(license_, options_.product, *fp_, now, last);
    if ((s == Status::Valid || s == Status::Expired || s == Status::OfflineTooLong) && (!last || now > *last)) write("license.seen", encode_history(now));
    return {s, license_};
}

CheckResult Client::check() {
    CheckResult r = evaluate_local();
    bool due = r.valid() && (options_.refresh_on_startup || now_ms() >= r.license->refresh_after_ms);
    if (due || r.status == Status::Expired || r.status == Status::Suspended || r.status == Status::OfflineTooLong ||
        r.status == Status::ClockTampered || r.status == Status::Unverified) {
        std::vector<std::string> anomalies;
        if (r.status == Status::ClockTampered) anomalies.push_back("clock_rollback");
        if (r.status == Status::Unverified) anomalies.push_back("history_missing");
        refresh(anomalies);
        r = evaluate_local();
    }
    if (r.license && r.license->test) std::cerr << "[licenserail] Test license: not for production use.\n";
    return r;
}

HttpResponse Client::post(const std::string& path, const std::string& body) {
    std::string base = options_.server_url;
    while (!base.empty() && base.back() == '/') base.pop_back();
    HttpResponse r = options_.transport(base + path, body, options_.timeout_seconds);
    // Not our server (a captive portal, a proxy): the same as being offline. Ours answers 204 or a JSON object.
    if (is_ok(r.status) && r.status != 204 && !json::parse(r.body, nullptr, false).is_object()) return {};
    return r;
}

ActivationResult Client::activate(const std::string& key, const std::string& machine_name) {
    if (key.empty()) return {false, "bad_request", "Enter the license key."};
    // It would only use up a seat.
    if (!fp().matches(fp())) return {false, "device_not_identified", "This device can't be identified, so a license can't be activated on it."};
    std::string name = !machine_name.empty() ? machine_name : !options_.machine_name.empty() ? options_.machine_name : "Device";
    json body = {{"licenseKey", key}, {"product", options_.product}, {"fingerprint", fp_json(fp())}, {"machineName", name},
                 {"appVersion", options_.app_version}};
    HttpResponse r = post("/api/client/v2/activate", body.dump());
    json j = json::parse(r.body, nullptr, false);
    if (r.status == 400 && text(j, "message").find("floating") != std::string::npos) {
        r = post("/api/client/v2/floating/checkout", body.dump());
        j = json::parse(r.body, nullptr, false);
    }
    if (r.status == 0) return {false, "network", "Could not connect to the license server."};
    if (!is_ok(r.status)) return {false, text(j, "code"), text(j, "message", "Server error.")};
    if (!save_if_valid(text(j, "token"))) return {false, "invalid_token", "The server returned an invalid license."};
    CheckResult c = evaluate_local();
    return c.valid() ? ActivationResult{true, "", "The license has been activated."} : ActivationResult{false, to_string(c.status), to_string(c.status)};
}

ActivationResult Client::deactivate() {
    std::string token = read("license.lic");
    if (token.empty()) return {true, "", "There is no license on this device."};
    auto p = verify_token(token, options_.public_key_pem);
    json body = {{"token", token}, {"fingerprint", fp_json(fp())}};
    HttpResponse r = post(p && p->floating ? "/api/client/v2/floating/release" : "/api/client/v2/deactivate", body.dump());
    if (r.status == 0) return {false, "network", "Removing the license needs an internet connection."};
    json j = json::parse(r.body, nullptr, false);
    std::string code = text(j, "code");
    if (!is_ok(r.status) && !is_revoking_code(code)) return {false, code, text(j, "message", "Server error.")};
    remove("license.lic");
    return {true, "", "The license has been removed from this device."};
}

bool Client::refresh(const std::vector<std::string>& anomalies) {
    std::string token = read("license.lic");
    if (token.empty()) return false;
    auto p = verify_token(token, options_.public_key_pem);
    json body = {{"token", token}, {"fingerprint", fp_json(fp())}, {"appVersion", options_.app_version}};
    body["anomalies"] = anomalies.empty() ? json(nullptr) : json(anomalies);
    HttpResponse r = post(p && p->floating ? "/api/client/v2/floating/heartbeat" : "/api/client/v2/refresh", body.dump());
    if (r.status == 0) return false;
    json j = json::parse(r.body, nullptr, false);
    if (is_ok(r.status)) return save_if_valid(text(j, "token"));
    std::string code = text(j, "code");
    if (is_revoking_code(code) || code == "lease_expired") {
        remove("license.lic");
        last_server_message_ = text(j, "message");
    }
    return false;
}

bool Client::save_if_valid(const std::string& token) {
    auto p = verify_token(token, options_.public_key_pem);
    std::string a = p ? p->product : "", b = options_.product;
    for (auto& c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!p || a != b) return false;
    fp();
    write("license.lic", token);
    write("license.seen", encode_history(now_ms()));
    return true;
}

std::string Client::read(const std::string& name) const { return read_file((fs::path(dir_) / name).string()).value_or(""); }

void Client::write(const std::string& name, const std::string& value) const {
    std::error_code ec;
    fs::create_directories(dir_, ec);
    std::ofstream(fs::path(dir_) / name, std::ios::trunc) << value;
}

void Client::remove(const std::string& name) const {
    std::error_code ec;
    fs::remove(fs::path(dir_) / name, ec);
}

}  // namespace licenserail
