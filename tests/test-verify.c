#include "verify.h"
#include "signature.h"
#include "public_key.h"

#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    int ret;
    FILE *fp = NULL;
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

    ret = verify(&pub, &sig, "files/vmImage");
    if(ret < 0)
        goto exit;

    ret = stat("files/vmImage", &st);
    if(ret < 0)
        goto exit;

    data = malloc(st.st_size);
    data_backup = malloc(st.st_size);
    if(!data) {
        ret = -errno;
        goto exit;
    }

    fp = fopen("files/vmImage", "r");
    if(!fp) {
        ret = -errno;
        goto exit;
    }

    if(fread(data, sizeof(uint8_t), st.st_size, fp) != (size_t)st.st_size) {
        ret = -1;
        goto exit;
    }

    memcpy(data_backup, data, st.st_size);

    ret = verify_buffer(&pub, &sig, data, (uint32_t)st.st_size);
    if(ret < 0)
        goto exit;

    ret = memcmp(data, data_backup, st.st_size) != 0;
exit:
    if(fp)
        fclose(fp);

    signature_destroy(&sig);
    public_key_destroy(&pub);
    free(data);
    free(data_backup);

    return ret;
}
