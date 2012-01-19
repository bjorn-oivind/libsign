#include "signature.h"

#include "mpi.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/* 5.2 */
int process_signature_packet(const uint8_t **data, uint64_t *datalen,
                             libsign_signature *ctx)
{
    int ret = -EINVAL, subdatalen;
    const uint8_t *p = *data;
    uint64_t tmplen = *datalen;
    uint32_t hashed_len;
    uint8_t *hashed_data;
    const uint8_t *hashed_data_start;

    /* signature packet must be at least 12 bytes long */
    if(*datalen < 12) {
        printf("foo\n");
        goto short_packet;
    }

    /* hashed data begins */
    hashed_data_start = p;

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
    if(tmplen < subdatalen) {
        printf("bar\n");
        goto short_packet;
    }

    /* we now know the length of the hashed data.
       (version + type + public key algorithm + length of hashed
       subpackets + hashed subpackets). */
    ctx->hashed_data_len = 6 + subdatalen;

    /* copy the hashed data into a new buffer so it will stick around after
       parsing. */
    ctx->hashed_data_start = malloc(ctx->hashed_data_len);
    if(!ctx->hashed_data_start) {
        ret = -ENOMEM;
        goto exit;
    }
    hashed_len = ctx->hashed_data_len;
    hashed_data = ctx->hashed_data_start;
    while(hashed_len--)
        *hashed_data++ = *hashed_data_start++;

    if(subdatalen) {
        process_signature_subpackets(&p, &tmplen, subdatalen, ctx);
    }
    /* end of hashed data */

    /* unhashed subpackets */
    subdatalen = *p++ << 8;
    subdatalen |= *p++;
    tmplen -= 2;

    /* do we have enough data? */
    if(tmplen < subdatalen) {
        free(ctx->hashed_data_start);
        goto short_packet;
    }

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
            free(ctx->hashed_data_start);
            mpz_clear(ctx->s);
            goto short_packet;
        }
        break;
    default:
        fprintf(stderr, "Unhandled public key algorithm.\n");
        free(ctx->hashed_data_start);
        ret = -ENOTSUP;
        goto exit;
    }

    *datalen -= (p - *data);
    *data = p;

    ret = 0;

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
