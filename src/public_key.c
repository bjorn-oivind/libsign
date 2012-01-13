#include "public_key.h"

#include "mpi.h"

#include <errno.h>
#include <stdio.h>

/* 5.5.2 */
int process_public_key_packet(const uint8_t **data, uint64_t *datalen,
                              libsign_public_key *ctx)
{
    int ret = 0;
    const uint8_t *p = *data;
    uint64_t tmplen = *datalen;

    /* public key packet must be at least 8 bytes:
       version, creation time, pk algorithm, at least one MPI */
    if(tmplen < 8)
        goto short_packet;

    ctx->version = *p++;
    ctx->created = (*p++ << 24);
    ctx->created |= (*p++ << 16);
    ctx->created |= (*p++ << 8);
    ctx->created |= (*p++);
    ctx->pk_algo = *p++;
    tmplen -= 6;

    switch(ctx->pk_algo) {
    case PGP_RSA:
        /* RSA public modulus n */
        mpz_init(ctx->n);
        if(mpi_to_mpz(&p, &tmplen, &ctx->n) != 0) {
            mpz_clear(ctx->n);
            goto short_packet;
        }

        /* RSA public encryption exponent e */
        mpz_init(ctx->e);
        if(mpi_to_mpz(&p, &tmplen, &ctx->e) != 0) {
            mpz_clear(ctx->n);
            mpz_clear(ctx->e);
            goto short_packet;
        }
        break;
    default:
        fprintf(stderr, "Unhandled public key algorithm.\n");
        ret = -ENOTSUP;
        goto exit;
    }

    *datalen -= (p - *data);
    *data = p;

exit:
    return ret;

short_packet:
    fprintf(stderr, "Unexpected end in public key packet.\n");
    return -EINVAL;
}

int process_public_subkey_packet(const uint8_t **data, int *datalen,
                                 libsign_public_key *ctx)
{
    return -EINVAL;
}
