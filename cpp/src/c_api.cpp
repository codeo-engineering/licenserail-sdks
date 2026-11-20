#include "licenserail/licenserail_c.h"

#include "licenserail/client.hpp"

struct licenserail_client {
    licenserail::Client client;
    std::string message;
};

extern "C" {

licenserail_client* licenserail_create(const char* server_url, const char* vendor, const char* product, const char* public_key_pem, const char* app_version,
                                       const char* storage_dir) {
    if (!server_url || !vendor || !product || !public_key_pem) return nullptr;
    licenserail::Options o;
    o.server_url = server_url;
    o.vendor = vendor;
    o.product = product;
    o.public_key_pem = public_key_pem;
    if (app_version) o.app_version = app_version;
    if (storage_dir) o.storage_dir = storage_dir;
    try {
        return new licenserail_client{licenserail::Client(o), {}};
    } catch (...) {
        return nullptr;
    }
}

void licenserail_destroy(licenserail_client* c) { delete c; }

licenserail_status licenserail_check(licenserail_client* c) {
    if (!c) return LICENSERAIL_MISSING;
    return static_cast<licenserail_status>(static_cast<int>(c->client.check().status));
}

int licenserail_activate(licenserail_client* c, const char* key) {
    if (!c || !key) return 0;
    auto r = c->client.activate(key);
    c->message = r.message;
    return r.success ? 1 : 0;
}

int licenserail_deactivate(licenserail_client* c) {
    if (!c) return 0;
    auto r = c->client.deactivate();
    c->message = r.message;
    return r.success ? 1 : 0;
}

const char* licenserail_last_message(licenserail_client* c) { return c ? c->message.c_str() : ""; }

int licenserail_has_feature(licenserail_client* c, const char* code) {
    return c && code && c->client.license() && c->client.license()->has_feature(code) ? 1 : 0;
}

}  // extern "C"
