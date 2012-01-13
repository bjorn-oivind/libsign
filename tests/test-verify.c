#include "verify.h"
#include "packet.h"

#include <stdlib.h>

libsign_public_key *pub_ctx = NULL;
libsign_signature *sig_ctx = NULL;

void signature_parsed(libsign_signature *s)
{
    if(sig_ctx) {
        mpz_clear(sig_ctx->s);
        free(sig_ctx);
    }
    sig_ctx = s;
}

void public_key_parsed(libsign_public_key *p)
{
    if(pub_ctx) {
        mpz_clear(pub_ctx->n);
        mpz_clear(pub_ctx->e);
        free(pub_ctx);
    }
    pub_ctx = p;
}

int main(int argc, char **argv)
{
    /* parse the packets from the public key and signature files */
    int ret;

    packet_parsed_callbacks callbacks = {
        .signature_parsed = &signature_parsed,
        .public_key_parsed = &public_key_parsed,
        .secret_key_parsed = &dummy_fallback,
    };

    set_callbacks(&callbacks);

    ret = process_packets_from_file("files/pubkey.key");
    if(ret < 0)
        return ret;

    ret = process_packets_from_file("files/vmImage.sig");
    if(ret < 0)
        return ret;

    ret = rsa_sha1_verify_file(pub_ctx, sig_ctx, "files/vmImage");

    mpz_clear(sig_ctx->s);
    mpz_clear(pub_ctx->n);
    mpz_clear(pub_ctx->e);

    free(sig_ctx);
    free(pub_ctx);

    if(ret != 0)
        return ret;

    return 0;
}
