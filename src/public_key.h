#ifndef __LIBSIGN_PUBLIC_KEY_H
#define __LIBSIGN_PUBLIC_KEY_H

#include <stdint.h>

#include <nettle/pgp.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pgp_key_version {
    PGP_KEY_VER3    = 3,
    PGP_KEY_VER4    = 4
};

struct libsign_public_key {
    enum pgp_key_version version;
    uint32_t created;
    enum pgp_public_key_algorithm pk_algo;

    mpz_t n;
    mpz_t e;
} typedef libsign_public_key;

int process_public_key_packet(const uint8_t **data, uint64_t *datalen,
                              libsign_public_key *ctx);
int process_public_subkey_packet(const uint8_t **data, int *datalen,
                                 libsign_public_key *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PUBLIC_KEY_H */
