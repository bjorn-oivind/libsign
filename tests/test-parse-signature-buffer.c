#include "signature.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    int ret, fd, armored = 0;
    FILE *fp;
    struct stat stbuf;
    uint32_t filesize, filename_len;
    uint8_t *buffer;
    const char *filename = SIGFILE;

    libsign_signature sig;

    signature_init(&sig);

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

    if(armored)
        ret = parse_signature_armor_buffer(&sig, buffer, filesize);
    else
        ret = parse_signature_buffer(&sig, buffer, filesize);

free_buffer:
    free(buffer);
close_fp:
    fclose(fp);
close_fd:
    close(fd);
exit:
    signature_destroy(&sig);

    return ret;
}
