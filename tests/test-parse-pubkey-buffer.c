#include "public_key.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <unistd.h>
#define O_BINARY 0
#endif

int main()
{
    int ret = -1, fd, armored = 0;
    struct stat stbuf;
    uint32_t filesize, filename_len;
    uint8_t *buffer;
    const char *filename = KEYFILE;

    libsign_public_key pub;

    public_key_init(&pub);

    /* examine the filename to see if the file is armored */
    filename_len = strlen(filename);

    /* is this an ascii armored file? */
    if(filename_len > 4 && strncmp(filename + (filename_len-4), ".asc", 4) == 0)
        armored = 1;

    fd = open(filename, O_RDONLY | O_BINARY);
    if(fd == -1) {
        goto exit;
    }

    /* find size of file */
    if(fstat(fd, &stbuf) == -1)
        goto close_fd;

    filesize = stbuf.st_size;
    buffer = malloc(filesize);
    if(!buffer)
        goto close_fd;

    /* read file into memory */
    if(read(fd, buffer, filesize) != filesize)
        goto free_buffer;

    if(armored)
        ret = parse_public_key_armor_buffer(&pub, buffer, filesize);
    else
        ret = parse_public_key_buffer(&pub, buffer, filesize);

free_buffer:
    free(buffer);
close_fd:
    close(fd);
exit:
    public_key_destroy(&pub);

    return ret;
}
