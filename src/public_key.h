#ifndef __LIBSIGN_PUBLIC_KEY_H
#define __LIBSIGN_PUBLIC_KEY_H

#include <stdint.h>
#include <gmp.h>

#include "pgp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libsign_userid {
    char *userid;
} libsign_userid;

typedef struct libsign_public_key {
    enum pgp_key_version version;
    libsign_timestamp created;
    enum pgp_public_key_algorithm pk_algo;

    uint8_t num_userids;
    libsign_userid *userids;

    /* TODO: should be placed in an RSA-specific struct */
    mpz_t n;
    mpz_t e;
} libsign_public_key;

void public_key_init(libsign_public_key *pub);
void public_key_destroy(libsign_public_key *pub);

int parse_public_key(libsign_public_key *pub, const char *filename);
int parse_public_key_buffer(libsign_public_key *pub, const uint8_t *buffer,
                            uint32_t datalen);
int parse_public_key_armor_buffer(libsign_public_key *pub, const uint8_t *buffer,
                                  uint32_t datalen);

int process_public_key_packet(const uint8_t **data, uint32_t *datalen,
                              libsign_public_key *ctx);
int process_public_key_uid_packet(const uint8_t **data, uint32_t *datalen,
                                  libsign_public_key *ctx);
int process_public_key_signature_packet(const uint8_t **data, uint32_t *datalen,
                                        libsign_public_key *ctx);
int process_public_key_subkey_packet(const uint8_t **data, uint32_t *datalen,
                                     libsign_public_key *ctx);

int decode_public_key_armor(const uint8_t *data, uint32_t datalen, uint8_t **plain_out,
                            uint32_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PUBLIC_KEY_H */
