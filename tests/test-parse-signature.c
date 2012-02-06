#include "signature.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int ret;

    libsign_signature sig;

    signature_init(&sig);

    ret = parse_signature(&sig, SIGFILE);

    signature_destroy(&sig);

    return ret;
}
