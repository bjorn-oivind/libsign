#include "public_key.h"
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
    FILE *fp;
    struct stat stbuf;
    uint64_t filesize;
    uint32_t filename_len;
    uint8_t *buffer;
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
        if(decode_public_key_armor(&buffer, &filesize) != 0)
            goto free_buffer;
    }

    p = buffer;

    ret = parse_public_key_buffer(pub, p, filesize);

free_buffer:
    free(buffer);
close_fp:
    fclose(fp);
close_fd:
    close(fd);
exit:
    return ret;
}

int parse_public_key_buffer(libsign_public_key *pub, const uint8_t *buffer,
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

/* 5.5.2 */
int process_public_key_packet(const uint8_t **data, uint64_t *datalen,
                              libsign_public_key *ctx)
{
    int ret = -EINVAL;
    const uint8_t *p = *data;
    uint64_t tmplen = *datalen;

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

int process_public_key_uid_packet(const uint8_t **data, uint64_t *datalen,
                                  libsign_public_key *ctx)
{
    const uint8_t *p = *data;

    int i, index = ctx->num_userids;

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

int process_public_key_signature_packet(const uint8_t **data, uint64_t *datalen,
                                        libsign_public_key *ctx)
{
    /* TODO: parse this properly */
    *data += *datalen;
    *datalen = 0;

    return 0;
}

int process_public_key_subkey_packet(const uint8_t **data, uint64_t *datalen,
                                     libsign_public_key *ctx)
{
    /* TODO: parse this properly */
    *data += *datalen;
    *datalen = 0;

    return 0;
}

int decode_public_key_armor(uint8_t **data, uint64_t *datalen)
{
    /* (6.2) for public keys, the armor header line shall be
       "-----BEGIN PGP PUBLIC KEY BLOCK-----" */
    if(*datalen < 36)
        goto error;

    if(strncmp((char*)*data, "-----BEGIN PGP PUBLIC KEY BLOCK-----", 36) != 0)
        goto error;

    return decode_armor(data, datalen);

error:
    return -EINVAL;
}
