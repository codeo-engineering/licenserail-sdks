#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>

#include "licenserail/client.hpp"

static std::string env(const char* name) {
    const char* v = std::getenv(name);
    return v ? v : "";
}

static std::string quote(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += (static_cast<unsigned char>(c) < 0x20) ? ' ' : c;
    }
    return out + "\"";
}

static void put(const licenserail::ActivationResult& r) {
    std::cout << "{\"success\":" << (r.success ? "true" : "false") << ",\"errorCode\":" << quote(r.error_code) << ",\"message\":" << quote(r.message) << "}\n";
}

int main(int, char** argv) {
    std::ifstream pem(env("LR_PUBLIC_KEY_FILE"));
    licenserail::Options o;
    o.server_url = env("LR_URL");
    o.vendor = env("LR_VENDOR");
    o.product = env("LR_PRODUCT");
    o.public_key_pem = std::string(std::istreambuf_iterator<char>(pem), {});
    o.storage_dir = env("LR_STORAGE");
    o.app_version = "1.2.3";
    o.timeout_seconds = std::stoi(env("LR_TIMEOUT"));
    std::istringstream device(env("LR_DEVICE"));
    licenserail::Fingerprint f;
    if (std::getline(device, f.machine_id, ',') && std::getline(device, f.disk_id, ',') && std::getline(device, f.host_name, ',') &&
        std::getline(device, f.board_id, ',')) {
        f.os = "linux";
        o.fingerprint = f;
    }
    licenserail::Client client(o);
    std::string op = argv[1];
    if (op == "activate") put(client.activate(argv[2]));
    else if (op == "deactivate") put(client.deactivate());
    else if (op == "refresh") std::cout << "{\"success\":" << (client.refresh() ? "true" : "false") << "}\n";
    else {
        auto r = client.check();
        std::cout << "{\"status\":" << quote(licenserail::to_string(r.status)) << ",\"features\":[";
        if (r.license)
            for (size_t i = 0; i < r.license->entitlements.size(); i++) std::cout << (i ? "," : "") << quote(r.license->entitlements[i]);
        std::cout << "],\"test\":" << (r.license && r.license->test ? "true" : "false") << "}\n";
    }
}
