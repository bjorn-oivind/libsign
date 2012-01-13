#include "signature.h"

#include "mpi.h"

#include <errno.h>
#include <stdio.h>

/* 5.2 */
int process_signature_packet(const uint8_t **data, uint64_t *datalen,
                             libsign_signature *ctx)
{
    int ret = 0, subdatalen;
    const uint8_t *p = *data;
    uint64_t tmplen = *datalen;

    /* signature packet must be at least 12 bytes long */
    if(*datalen < 12)
        goto short_packet;

    /* hashed data begins */
    ctx->hashed_data_start = p;

    /* signature version */
    ctx->version = *p++;
    if(ctx->version != PGP_SIG_VER4) {
        fprintf(stderr, "Unhandled signature version.");
        ret = -ENOTSUP;
        goto exit;
    }

    /* type */
    ctx->type = *p++;
    /* public key algorithm */
    ctx->pk_algo = *p++;
    /* hash algorithm */
    ctx->hash_algo = *p++;
    tmplen -= 4;

    /* hashed subpackets */
    subdatalen = *p++ << 8;
    subdatalen |= *p++;
    tmplen -= 2;

    /* do we have enough data? */
    if(tmplen < subdatalen)
        goto short_packet;

    /* we now know the length of the hashed data.
       (version + type + public key algorithm + length of hashed
       subpackets + hashed subpackets). */
    ctx->hashed_data_len = 6 + subdatalen;

    if(subdatalen) {
        process_signature_subpackets(&p, &tmplen, subdatalen, ctx);
    }
    /* end of hashed data */

    /* unhashed subpackets */
    subdatalen = *p++ << 8;
    subdatalen |= *p++;
    tmplen -= 2;

    /* do we have enough data? */
    if(tmplen < subdatalen)
        goto short_packet;

    if(subdatalen) {
        process_signature_subpackets(&p, &tmplen, subdatalen, ctx);
    }

    /* short hash */
    ctx->short_hash = *p++ << 8;
    ctx->short_hash |= *p++;
    tmplen -= 2;

    /* algorithm specific data */
    switch(ctx->pk_algo) {
    case PGP_RSA:
        /* RSA signature value m ** d mod n. */
        mpz_init(ctx->s);
        if(mpi_to_mpz(&p, &tmplen, &ctx->s) != 0) {
            mpz_clear(ctx->s);
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
    fprintf(stderr, "Unexpected end in signature packet.\n");
    return -EINVAL;
}

int process_signature_subpackets(const uint8_t **data, uint64_t *datalen,
                                 int subdatalen, libsign_signature *ctx)
{
    /* TODO: parse subpackets. Length has already been checked. */
    const uint8_t *p = *data;
    p += subdatalen;
    *datalen -= subdatalen;
    *data = p;
    return 0;
}
