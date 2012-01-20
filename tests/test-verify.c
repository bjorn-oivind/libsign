#include "verify.h"
#include "signature.h"
#include "public_key.h"

int main(int argc, char **argv)
{
    int ret;

    libsign_signature sig;
    libsign_public_key pub;

    signature_init(&sig);
    public_key_init(&pub);

    ret = parse_public_key(&pub, KEYFILE);
    if(ret < 0)
        goto exit;

    ret = parse_signature(&sig, SIGFILE);
    if(ret < 0)
        goto destroy_pub;

    ret = verify(&pub, &sig, "files/vmImage");

destroy_sig:
    signature_destroy(&sig);
destroy_pub:
    public_key_destroy(&pub);
exit:
    return ret;
}
