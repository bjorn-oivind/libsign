#include "signature.h"
#include "armor.h"
#include "packet.h"
#include "mpi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <unistd.h>
#define O_BINARY 0
#endif

void signature_init(libsign_signature *sig)
{
    memset(sig, 0, sizeof(libsign_signature));
    mpz_init(sig->s);
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
    struct stat stbuf;
    uint32_t filesize, filename_len, plain_len;
    uint8_t *buffer, *plaintext;
    const uint8_t *p;

    /* examine the filename to see if the file is armored */
    filename_len = strlen(filename);

    /* is this an ascii armored file? */
    if(filename_len > 4 && strncmp(filename + (filename_len-4), ".asc", 4) == 0)
        armored = 1;

    fd = open(filename, O_RDONLY | O_BINARY);
    if(fd == -1) {
        goto exit;
    }

    /* find size of file */
    if(fstat(fd, &stbuf) == -1)
        goto close_fd;

    filesize = stbuf.st_size;
    buffer = malloc(filesize);
    if(!buffer)
        goto close_fd;

    /* read file into memory */
    if(read(fd, buffer, filesize) != filesize)
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

    if(armored)
        free(plaintext);

free_buffer:
    free(buffer);
close_fd:
    close(fd);
exit:
    return ret;
}

int parse_signature_buffer(libsign_signature *sig, const uint8_t *buffer,
                           uint32_t datalen)
{
    int ret = -EINVAL;
    uint32_t packet_size;

    if(!datalen)
        goto exit;

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
                                 uint32_t datalen)
{
    int ret = -EINVAL;
    uint8_t *plaintext = NULL;
    uint32_t plain_len;

    ret = decode_signature_armor(buffer, datalen, &plaintext, &plain_len);
    if(ret < 0)
        goto exit;

    ret = parse_signature_buffer(sig, plaintext, plain_len);

exit:
    free(plaintext);

    return ret;
}

/* 5.2 */
int process_signature_packet(const uint8_t **data, uint32_t *datalen,
                             libsign_signature *ctx)
{
    int ret = -EINVAL;
    const uint8_t *p = *data;
    uint32_t subdatalen, hashed_len, tmplen = *datalen;
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
        if((ret = process_signature_subpackets(&p, &tmplen, subdatalen, ctx)))
            goto free_hashed_data;
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
        if((ret = process_signature_subpackets(&p, &tmplen, subdatalen, ctx)))
            goto free_hashed_data;
    }

    /* short hash */
    ctx->short_hash = *p++ << 8;
    ctx->short_hash |= *p++;
    tmplen -= 2;

    /* algorithm specific data */
    switch(ctx->pk_algo) {
    case PGP_RSA:
        /* RSA signature value m ** d mod n. */
        if(mpi_to_mpz(&p, &tmplen, &ctx->s) != 0)
            goto free_hashed_data;

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

int process_signature_subpackets(const uint8_t **data, uint32_t *datalen,
                                 int subdatalen, libsign_signature *ctx)
{
    int ret = -EINVAL;
    const uint8_t *p = *data;
    while(subdatalen) {
        const uint8_t *prev = p;
        /* find length of subpacket (5.2.3.1) */
        uint32_t len;
        /* one octet length */
        if(*p < 192)
            len = *p++;
        /* two octet length */
        else if(*p < 255) {
            len = ((*p++) - 192) << 8;
            len += (*p++) + 192;
        }
        /* five octet length */
        else {
            /* length is represented as a four octet scalar starting at second octet */
            p++;
            len = (*p++ << 24);
            len |= (*p++ << 16);
            len |= (*p++ << 8);
            len |= (*p++);
        }
        /* p now points at the type octet */
        /* len includes the type octet, we're going to consume this in the switch, so decrement len here */
        len--;
        switch(*p++) {
        case PGP_SIG_CREATION_TIME:
            /* 5.2.3.4 - 4 octet time field */
            if(len != 4)
                goto exit;

            ctx->creation_time = (*p++ << 24);
            ctx->creation_time |= (*p++ << 16);
            ctx->creation_time |= (*p++ << 8);
            ctx->creation_time |= (*p++);
            break;
        case PGP_SIG_ISSUER:
            /* 5.2.3.5 - 8 octet key id */
            if(len != 8)
                goto exit;

            ctx->issuer = ((uint64_t)(*p++) << 56);
            ctx->issuer |= ((uint64_t)(*p++) << 48);
            ctx->issuer |= ((uint64_t)(*p++) << 40);
            ctx->issuer |= ((uint64_t)(*p++) << 32);
            ctx->issuer |= ((uint64_t)(*p++) << 24);
            ctx->issuer |= ((uint64_t)(*p++) << 16);
            ctx->issuer |= ((uint64_t)(*p++) << 8);
            ctx->issuer |= (*p++);
            break;
        default:
            /* TODO: support all subtypes */
            p += len;
            break;
        }
        subdatalen -= (p - prev);
        *datalen -= (p - prev);
    }

    *data = p;

    ret = 0;

exit:
    return ret;
}

int decode_signature_armor(const uint8_t *data, uint32_t datalen, uint8_t **plain_out,
                           uint32_t *plain_len)
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
