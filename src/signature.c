#include "signature.h"
#include "armor.h"
#include "packet.h"
#include "mpi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

void signature_init(libsign_signature *sig)
{
    mpz_init(sig->s);
    sig->hashed_data = NULL;
}

void signature_destroy(libsign_signature *sig)
{
    free(sig->hashed_data);
    mpz_clear(sig->s);
}

int parse_signature(libsign_signature *sig, const char *filename)
{
    /* open the file pointed to by filename and read contents into memory */
    int armored = 0, fd, ret = -EINVAL;
    FILE *fp;
    struct stat stbuf;
    uint64_t filesize, plain_len;
    uint32_t filename_len;
    uint8_t *buffer, *plaintext;
    const uint8_t *p;

    /* examine the filename to see if the file is armored */
    filename_len = strlen(filename);

    /* is this an ascii armored file? */
    if(filename_len > 4 && strncmp(filename + (filename_len-4), ".asc", 4) == 0)
        armored = 1;

    fd = open(filename, O_RDONLY);
    if(fd == -1) {
        goto exit;
    }

    fp = fdopen(fd, "rb");
    if(!fp)
        goto close_fd;

    /* find size of file */
    if(fstat(fd, &stbuf) == -1)
        goto close_fp;

    filesize = stbuf.st_size;
    buffer = malloc(filesize);
    if(!buffer)
        goto close_fp;

    /* read file into memory */
    if(fread((uint8_t*)buffer, filesize, 1, fp) == 0)
        goto free_buffer;

    /* do we have to decode the armor? */
    if(armored) {
        if(decode_signature_armor(buffer, filesize, &plaintext, &plain_len) != 0)
            goto free_buffer;
        p = plaintext;
        filesize = plain_len;
    }
    else
        p = buffer;

    ret = parse_signature_buffer(sig, p, filesize);

free_armor:
    if(armored)
        free(plaintext);

free_buffer:
    free(buffer);
close_fp:
    fclose(fp);
close_fd:
    close(fd);
exit:
    return ret;
}

int parse_signature_buffer(libsign_signature *sig, const uint8_t *buffer,
                           uint64_t datalen)
{
    int ret = -EINVAL;
    uint64_t packet_size;

    /* parse packet headers */
    while(datalen) {
        int tag = parse_packet_header(&buffer, &datalen, &packet_size);
        if(tag < 0)
            goto exit;

        datalen -= packet_size;

        switch(tag) {
        case PGP_TAG_SIGNATURE:
            ret = process_signature_packet(&buffer, &packet_size, sig);
            if(ret < 0)
                goto exit;
            break;
        }
    }

    ret = 0;

exit:
    return ret;
}

int parse_signature_armor_buffer(libsign_signature *sig, const uint8_t *buffer,
                                 uint64_t datalen)
{
    int ret = -EINVAL;
    uint8_t *plaintext = NULL;
    uint64_t plain_len;
    const uint8_t *p;

    ret = decode_public_key_armor(buffer, datalen, &plaintext, &plain_len);
    if(ret < 0)
        goto exit;

    p = plaintext;

    ret = parse_signature_buffer(sig, plaintext, plain_len);

exit:
    free(plaintext);

    return ret;
}

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
    if(tmplen < 12) {
        goto exit;
    }

    /* hashed data begins */
    hashed_data_start = p;

    /* signature version */
    ctx->version = *p++;
    if(ctx->version != PGP_SIG_VER4) {
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
        goto exit;
    }

    /* we now know the length of the hashed data.
       (version + type + public key algorithm + length of hashed
       subpackets + hashed subpackets). */
    ctx->hashed_data_len = 6 + subdatalen;

    /* copy the hashed data into a new buffer so it will stick around after
       parsing. */
    ctx->hashed_data = malloc(ctx->hashed_data_len);
    if(!ctx->hashed_data) {
        ret = -ENOMEM;
        goto exit;
    }
    hashed_len = ctx->hashed_data_len;
    hashed_data = ctx->hashed_data;
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
        goto free_hashed_data;
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
            mpz_clear(ctx->s);
            goto free_hashed_data;
        }
        break;
    default:
        ret = -ENOTSUP;
        goto free_hashed_data;
    }

    *datalen -= (p - *data);
    *data = p;

    ret = 0;

exit:
    return ret;

free_hashed_data:
    free(ctx->hashed_data);
    return ret;
}

int process_signature_subpackets(const uint8_t **data, uint64_t *datalen,
                                 int subdatalen, libsign_signature *ctx)
{
    /* TODO: parse subpackets. Length has already been checked. */
    *data += subdatalen;
    *datalen -= subdatalen;
    return 0;
}

int decode_signature_armor(const uint8_t *data, uint64_t datalen, uint8_t **plain_out,
                           uint64_t *plain_len)
{
    /* (6.2) for signatures, the armor header line shall be
      "-----BEGIN PGP SIGNATURE-----" */
    if(datalen < 29)
        goto error;

    if(strncmp((char*)data, "-----BEGIN PGP SIGNATURE-----", 29) != 0)
        goto error;

    return decode_armor(data, datalen, plain_out, plain_len);

error:
    return -EINVAL;
}
