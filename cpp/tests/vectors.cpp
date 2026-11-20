#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "licenserail/core.hpp"

using nlohmann::json;
using namespace licenserail;

static int failures = 0;
static void check(bool ok, const std::string& what) {
    if (!ok) { failures++; std::cout << "FAIL: " << what << "\n"; }
}

static json load(const std::string& dir, const std::string& name) {
    std::ifstream f(dir + "/" + name);
    return json::parse(f);
}

static Fingerprint fp(const json& j) {
    return {j["machineId"], j["diskId"], j["hostName"], j["boardId"], j.contains("os") && j["os"].is_string() ? j["os"].get<std::string>() : ""};
}

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : "../test-vectors";

    json tokens = load(dir, "tokens.json");
    for (const auto& c : tokens["cases"]) {
        auto p = verify_token(c["token"], tokens["publicKeyPem"]);
        check(p.has_value() == c["expect"]["signatureValid"].get<bool>(), "token " + c["name"].get<std::string>());
        if (p && c["expect"].contains("payload")) {
            const auto& e = c["expect"]["payload"];
            check(p->product == e["product"].get<std::string>(), "token product");
            check(p->customer == e["customer"].get<std::string>(), "token customer");
        }
    }
    for (const auto& c : load(dir, "fingerprint.json")["cases"]) {
        std::optional<std::string> raw = c["raw"].is_null() ? std::nullopt : std::optional<std::string>(c["raw"].get<std::string>());
        check(hash_component(c["product"], c["part"], raw) == c["hash"].get<std::string>(), "hash " + c["raw"].dump());
    }
    for (const auto& c : load(dir, "match.json")["cases"])
        check(fp(c["registered"]).matches(fp(c["presented"])) == c["matches"].get<bool>(), "match " + c["name"].get<std::string>());

    json ev = load(dir, "evaluate.json");
    for (const auto& c : ev["cases"]) {
        auto last = c["lastSeen"].is_null() ? std::nullopt : parse_time(c["lastSeen"]);
        Status s = evaluate(verify_token(c["token"], ev["publicKeyPem"]), c["product"], fp(c["machine"]), *parse_time(c["now"]), last);
        check(std::string(to_string(s)) == c["status"].get<std::string>(), "evaluate " + c["name"].get<std::string>() + " got " + to_string(s));
    }
    std::cout << (failures == 0 ? "All vectors passed.\n" : std::to_string(failures) + " vector(s) failed.\n");
    return failures == 0 ? 0 : 1;
}
