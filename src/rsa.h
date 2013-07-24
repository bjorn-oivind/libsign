/* Lifted in part from Nettle */

#ifndef __LIBSIGN_RSA_H
#define __LIBSIGN_RSA_H

#include <stddef.h>

#include <gmp.h>

#include "sha1.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rsa_public_key {
    /* Size of the modulo in octets */
    size_t size;

    /* Modulo */
    mpz_t n;

    /* Public exponent */
    mpz_t e;
} rsa_public_key;

void rsa_public_key_init(rsa_public_key *key);
int  rsa_public_key_prepare(rsa_public_key *key);
void rsa_public_key_clear(rsa_public_key *key);
int  rsa_sha1_verify(rsa_public_key *key, sha1_ctx *hash, mpz_t signature);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_RSA_H */
