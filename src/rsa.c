#include "rsa.h"

#include <errno.h>
#include <malloc.h>
#include <string.h>

static const uint8_t rsa_pkcs1_sha1_prefix[] = {
    0x30, 0x21, /* sequence */
    0x30, 0x09, /* sequence */
    0x06, 0x05, /* oid */
    0x2b, 0x0e, 0x03, 0x02, 0x1a, /* hash algorithm is SHA-1 */
    0x05, 0x00, /* null */
    0x04, 0x14  /* octet string */
    /* hash here */
};

void rsa_public_key_init(rsa_public_key *key)
{
    mpz_init(key->n);
    mpz_init(key->e);

    key->size = 0;
}

int rsa_public_key_prepare(rsa_public_key *key)
{
    key->size = ((mpz_sizeinbase(key->n, 2) + 7) / 8);

    /* for simplicity, don't support keys below 512 bit */
    if(key->size > 64)
        return -EMSGSIZE;

    return 0;
}

void rsa_public_key_clear(rsa_public_key *key)
{
    mpz_clear(key->n);
    mpz_clear(key->e);

    key->size = 0;
}

int rsa_sha1_verify(rsa_public_key *key, sha1_ctx *hash, mpz_t signature)
{
    int ret = -EBADMSG;
    mpz_t msg, expected;

    mpz_init(msg);

    /* add PKCS#1 prefix to hash, consists of 0x00, 0x01, 0xff ... 0xff, 0x00, id, hash */
    uint8_t *prefix, *p;

    prefix = malloc(key->size);
    if(!prefix)
        goto exit;

    int id_idx = key->size - SHA1_DIGEST_LENGTH - sizeof(rsa_pkcs1_sha1_prefix);

    p = prefix;
    *p++ = 0;
    *p++ = 1;
    memset(p, 0xff, id_idx - 3);
    p += id_idx - 3;
    *p++ = 0;

    memcpy(p, rsa_pkcs1_sha1_prefix, sizeof(rsa_pkcs1_sha1_prefix));
    p += sizeof(rsa_pkcs1_sha1_prefix);

    sha1_digest(hash, p);
    mpz_import(msg, key->size, 1, 1, 0, 0, prefix);

    mpz_init(expected);

    mpz_powm(expected, signature, key->e, key->n);

    ret = mpz_cmp(msg, expected);

    mpz_clear(expected);

exit:
    mpz_clear(msg);
    free(prefix);

    return ret;
}
