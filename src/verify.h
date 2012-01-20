#ifndef __LIBSIGN_VERIFY_H
#define __LIBSIGN_VERIFY_H

#include "public_key.h"
#include "signature.h"

#ifdef __cplusplus
extern "C" {
#endif

int verify(libsign_public_key *public_key, libsign_signature *signature, const char *filename);

int rsa_sha1_verify_file(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                         const char *filename);
int rsa_sha1_verify_fd(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                          int fd);
int rsa_sha1_verify_data(libsign_public_key *pub_ctx, libsign_signature *sig_ctx,
                          const uint8_t *data, uint64_t datalen);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_VERIFY_H */
