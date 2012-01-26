#include "verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <nettle/sha.h>
#include <nettle/rsa.h>

int verify(libsign_public_key *public_key, libsign_signature *signature, const char *filename)
{
    /* TODO: check key id for public key and signature here */
    switch(public_key->pk_algo) {
    case PGP_RSA:
        switch(signature->hash_algo) {
        case PGP_SHA1:
            return rsa_sha1_verify_file(public_key, signature, filename);
            break;
        default:
            return -ENOTSUP;
            break;
        }
        break;
    default:
        return -ENOTSUP;
        break;
    }
}

int verify_buffer(libsign_public_key *public_key, libsign_signature *signature,
                  const uint8_t *data, uint64_t datalen)
{
    /* TODO: check that the key id matches here */
    switch(public_key->pk_algo) {
    case PGP_RSA:
        switch(signature->hash_algo) {
        case PGP_SHA1:
            return rsa_sha1_verify_data(public_key, signature, data, datalen);
            break;
        default:
            return -ENOTSUP;
            break;
        }
    default:
        return -ENOTSUP;
        break;
    }
}

int rsa_sha1_verify_file(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                         const char *filename)
{
    /* open an fd and send the result to rsa_sha1_verify_fd. */
    int ret;
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        return -EINVAL;
    }

    ret = rsa_sha1_verify_fd(pub_ctx, sig_ctx, fd);

    close(fd);

    return ret;
}

int rsa_sha1_verify_fd(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                          int fd)
{
    /* read and verify the contents of file given by fd */
    int ret = -EINVAL;
    struct stat stbuf;
    uint64_t filesize;
    uint8_t *buffer;
    FILE *fp;

    fp = fdopen(fd, "rb");
    if(!fp)
        goto exit;

    /* find size of file */
    if(fstat(fd, &stbuf) == -1)
        goto close_fp;

    filesize = stbuf.st_size;
    buffer = malloc(filesize);
    if(!buffer) {
        ret = -ENOMEM;
        goto close_fp;
    }

    if(fread(buffer, filesize, 1, fp) == 0)
        goto free_buffer;

    ret = rsa_sha1_verify_data(pub_ctx, sig_ctx, (const uint8_t*)buffer, filesize);

free_buffer:
    free(buffer);
close_fp:
    fclose(fp);
exit:
    return ret;
}

/* 5.2.4 */
int rsa_sha1_verify_data(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                          const uint8_t *data, uint64_t datalen)
{
    int ret = -EINVAL;
    struct sha1_ctx hash;
    struct rsa_public_key key;

    rsa_public_key_init(&key);

    mpz_set(key.n, pub_ctx->n);
    mpz_set(key.e, pub_ctx->e);

    rsa_public_key_prepare(&key);

    /* first hash the data */
    sha1_init(&hash);
    sha1_update(&hash, datalen, data);
    /* hash the hashed data from the signature */
    sha1_update(&hash, sig_ctx->hashed_data_len,
                sig_ctx->hashed_data);
    /* then hash the trailer */
    if(sig_ctx->version == PGP_SIG_VER4) {
        uint8_t trailer[6];
        /* version */
        trailer[0] = 0x04;

        trailer[1] = 0xff;

        /* big-endian length of the hashed data from
           the signature */
        trailer[5] = sig_ctx->hashed_data_len;
        trailer[4] = sig_ctx->hashed_data_len >> 8;
        trailer[3] = sig_ctx->hashed_data_len >> 16;
        trailer[2] = sig_ctx->hashed_data_len >> 24;

        sha1_update(&hash, 6, trailer);
    }
    else {
        goto exit;
    }

    if(rsa_sha1_verify(&key, &hash, sig_ctx->s))
        ret = 0;

exit:
    rsa_public_key_clear(&key);

    return ret;
}
