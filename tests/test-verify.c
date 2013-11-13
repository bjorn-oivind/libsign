#include "verify.h"
#include "signature.h"
#include "public_key.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef _MSC_VER
#include <unistd.h>
#define O_BINARY 0
#endif

int main()
{
    int ret, fd = -1;
    struct stat st;
    uint8_t *data = NULL, *data_backup = NULL;

    libsign_signature sig;
    libsign_public_key pub;

    signature_init(&sig);
    public_key_init(&pub);

    ret = parse_public_key(&pub, KEYFILE);
    if(ret < 0)
        goto exit;

    ret = parse_signature(&sig, SIGFILE);
    if(ret < 0)
        goto exit;

    if(sig.issuer != 0x1EB5F06127342502ULL)
        goto exit;

    ret = verify(&pub, &sig, "files/vmImage");
    if(ret < 0)
        goto exit;

    fd = open("files/vmImage", O_BINARY);
    if(fd < 0)
        goto exit;

    ret = fstat(fd, &st);
    if(ret < 0)
        goto exit;

    data = malloc(st.st_size);
    data_backup = malloc(st.st_size);
    if(!data) {
        ret = -errno;
        goto exit;
    }

    if(read(fd, data, st.st_size) != (uint32_t)st.st_size) {
        ret = -1;
        goto exit;
    }

    memcpy(data_backup, data, st.st_size);

    ret = verify_buffer(&pub, &sig, data, (uint32_t)st.st_size);
    if(ret < 0)
        goto exit;

    ret = memcmp(data, data_backup, st.st_size) != 0;
exit:
    if(fd >= 0)
        close(fd);

    signature_destroy(&sig);
    public_key_destroy(&pub);
    free(data);
    free(data_backup);

    return ret;
}
