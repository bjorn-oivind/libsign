#include "public_key.h"
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

void public_key_init(libsign_public_key *pub)
{
    mpz_init(pub->n);
    mpz_init(pub->e);
    pub->userids = NULL;
    pub->num_userids = 0;
}

void public_key_destroy(libsign_public_key *pub)
{
    int i;

    mpz_clear(pub->n);
    mpz_clear(pub->e);

    for(i = 0; i < pub->num_userids; i++)
        free(pub->userids[i].userid);

    free(pub->userids);
}

int parse_public_key(libsign_public_key *pub, const char *filename)
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
        if(decode_public_key_armor(buffer, filesize, &plaintext, &plain_len) != 0)
            goto free_buffer;
        filesize = plain_len;
        p = plaintext;
    }
    else
        p = buffer;

    ret = parse_public_key_buffer(pub, p, filesize);

    if(armored)
        free(plaintext);

free_buffer:
    free(buffer);
close_fd:
    close(fd);
exit:
    return ret;
}

int parse_public_key_buffer(libsign_public_key *pub, const uint8_t *buffer,
                            uint32_t datalen)
{
    int ret = -EINVAL;
    uint32_t packet_size;

    /* parse packet headers */
    while(datalen) {
        int tag = parse_packet_header(&buffer, &datalen, &packet_size);
        if(tag < 0)
            goto exit;

        datalen -= packet_size;

        switch(tag) {
        case PGP_TAG_PUBLIC_KEY:
            ret = process_public_key_packet(&buffer, &datalen, pub);
            if(ret < 0)
                goto exit;
            break;
        case PGP_TAG_PUBLIC_SUBKEY:
            ret = process_public_key_subkey_packet(&buffer, &datalen, pub);
            if(ret < 0)
                goto exit;
            break;
        case PGP_TAG_SIGNATURE:
            ret = process_public_key_signature_packet(&buffer, &datalen, pub);
            if(ret < 0)
                goto exit;
            break;
        case PGP_TAG_USERID:
            ret = process_public_key_uid_packet(&buffer, &datalen, pub);
            if(ret < 0)
                goto exit;
            break;
        }
    }

    ret = 0;

exit:
    return ret;
}

int parse_public_key_armor_buffer(libsign_public_key *pub, const uint8_t *buffer,
                                  uint32_t datalen)
{
    int ret = -EINVAL;
    uint8_t *plaintext = NULL;
    uint32_t plain_len;

    ret = decode_public_key_armor(buffer, datalen, &plaintext, &plain_len);
    if(ret < 0)
        goto exit;

    ret = parse_public_key_buffer(pub, plaintext, plain_len);

exit:
    free(plaintext);

    return ret;
}

/* 5.5.2 */
int process_public_key_packet(const uint8_t **data, uint32_t *datalen,
                              libsign_public_key *ctx)
{
    int ret = -EINVAL;
    const uint8_t *p = *data;
    uint32_t tmplen = *datalen;

    /* public key packet must be at least 8 bytes:
       version, creation time, pk algorithm, at least one MPI */
    if(tmplen < 8)
        goto exit;

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
            goto exit;
        }

        /* RSA public encryption exponent e */
        mpz_init(ctx->e);
        if(mpi_to_mpz(&p, &tmplen, &ctx->e) != 0) {
            mpz_clear(ctx->n);
            mpz_clear(ctx->e);
            goto exit;
        }
        break;
    default:
        ret = -ENOTSUP;
        goto exit;
    }

    *datalen -= (p - *data);
    *data = p;

    ret = 0;

exit:
    return ret;
}

int process_public_key_uid_packet(const uint8_t **data, uint32_t *datalen,
                                  libsign_public_key *ctx)
{
    const uint8_t *p = *data;

    uint32_t i, index = ctx->num_userids;

    ctx->num_userids++;
    ctx->userids = realloc(ctx->userids, ctx->num_userids * sizeof(libsign_userid));

    if(!ctx->userids)
        return -ENOMEM;

    ctx->userids[index].userid = malloc(*datalen);
    if(!ctx->userids[index].userid)
        return -ENOMEM;

    for(i = 0; i < *datalen; i++)
        ctx->userids[index].userid[i] = *p++;

    *datalen = 0;
    *data = p;

    return 0;
}

int process_public_key_signature_packet(const uint8_t **data, uint32_t *datalen,
                                        libsign_public_key *ctx)
{
    /* TODO: parse this properly */
    (void)ctx;
    *data += *datalen;
    *datalen = 0;

    return 0;
}

int process_public_key_subkey_packet(const uint8_t **data, uint32_t *datalen,
                                     libsign_public_key *ctx)
{
    /* TODO: parse this properly */
    (void)ctx;
    *data += *datalen;
    *datalen = 0;

    return 0;
}

int decode_public_key_armor(const uint8_t *data, uint32_t datalen, uint8_t **plain_out,
                            uint32_t *plain_len)
{
    /* (6.2) for public keys, the armor header line shall be
       "-----BEGIN PGP PUBLIC KEY BLOCK-----" */
    if(datalen < 36)
        goto error;

    if(strncmp((char*)data, "-----BEGIN PGP PUBLIC KEY BLOCK-----", 36) != 0)
        goto error;

    return decode_armor(data, datalen, plain_out, plain_len);

error:
    return -EINVAL;
}
