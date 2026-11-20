/* LicenseRail C ABI: a stable C interface over the C++ client (for C, Delphi, Python ctypes, game engines...). */
#ifndef LICENSERAIL_C_H
#define LICENSERAIL_C_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct licenserail_client licenserail_client;

/* Status values match the shared statuses: 0 Valid, 1 Missing, 2 InvalidSignature, 3 WrongProduct, 4 WrongMachine, 5 Expired,
   6 OfflineTooLong, 7 ClockTampered, 8 Unverified, 9 Suspended. */
typedef enum {
    LICENSERAIL_VALID = 0, LICENSERAIL_MISSING, LICENSERAIL_INVALID_SIGNATURE, LICENSERAIL_WRONG_PRODUCT, LICENSERAIL_WRONG_MACHINE,
    LICENSERAIL_EXPIRED, LICENSERAIL_OFFLINE_TOO_LONG, LICENSERAIL_CLOCK_TAMPERED, LICENSERAIL_UNVERIFIED, LICENSERAIL_SUSPENDED
} licenserail_status;

/* Returns NULL on invalid arguments. storage_dir may be NULL (per-user default). */
licenserail_client* licenserail_create(const char* server_url, const char* vendor, const char* product, const char* public_key_pem, const char* app_version,
                                       const char* storage_dir);
void licenserail_destroy(licenserail_client* client);

licenserail_status licenserail_check(licenserail_client* client);
/* Returns 1 on success. The message (UTF-8) stays valid until the next call on this client. */
int licenserail_activate(licenserail_client* client, const char* license_key);
int licenserail_deactivate(licenserail_client* client);
const char* licenserail_last_message(licenserail_client* client);
int licenserail_has_feature(licenserail_client* client, const char* code);

#ifdef __cplusplus
}
#endif
#endif
