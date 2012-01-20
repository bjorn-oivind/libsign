#include "public_key.h"

int main(int argc, char **argv)
{
    int ret;

    libsign_public_key pub;

    public_key_init(&pub);

    ret = parse_public_key(&pub, KEYFILE);

    public_key_destroy(&pub);

    return ret;
}
