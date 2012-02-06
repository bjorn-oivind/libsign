#ifndef __LIBSIGN_SIGN_H
#define __LIBSIGN_SIGN_H

#include <stdint.h>

#include <pgp.h>
#include <bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pgp_sig_version {
    PGP_SIG_VER3    = 3,
    PGP_SIG_VER4    = 4
};

typedef struct libsign_signature
{
    enum pgp_sig_version version;
    enum pgp_signature_type type;
    enum pgp_public_key_algorithm pk_algo;
    enum pgp_hash_algorithm hash_algo;

    uint8_t *hashed_data;
    uint32_t hashed_data_len;

    uint16_t short_hash;

    mpz_t s;
} libsign_signature;

void signature_init(libsign_signature *sig);
void signature_destroy(libsign_signature *sig);

int parse_signature(libsign_signature *sig, const char *filename);
int parse_signature_buffer(libsign_signature *sig, const uint8_t *buffer,
                           uint32_t datalen);
int parse_signature_armor_buffer(libsign_signature *sig, const uint8_t *buffer,
                                 uint32_t datalen);

int process_signature_packet(const uint8_t **data, uint32_t *datalen,
                             libsign_signature *ctx);
int process_signature_subpackets(const uint8_t **data, uint32_t *datalen,
                                 int subdatalen, libsign_signature *ctx);

int decode_signature_armor(const uint8_t *data, uint32_t datalen, uint8_t **plain_out,
                           uint32_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif // __LIBSIGN_SIGN_H
