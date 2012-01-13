#include "packet.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* 4.2 */
int parse_packet_header(const uint8_t **data, uint64_t *datalen, uint64_t *packet_size)
{
    const uint8_t *p = *data;
    int newlen = *datalen;
    /* datalen must be at least two bytes */
    if(*datalen < 2)
        goto short_packet;

    uint8_t tag = *p++;

    if(!(tag & 0x80)) {
        fprintf(stderr, "Packet does not have MSB set. Not a PGP packet.\n");
        return -EINVAL;
    }

    tag &= ~0x80;

    /* is it a new format header? (4.2.2) */
    if(tag & 0x40) {
        printf("New packet length format found.\n");
        tag &= ~0x40;
        switch(*p) {
        case 0x00 ... 0xbf:
            /* one byte length (4.2.2.1) */
            *packet_size = *p++;
            break;
        case 0xc0 ... 0xdf:
            /* two byte length (4.2.2.2) */
            /* datalen must be at least three bytes */
            if(*datalen < 3)
                goto short_packet;

            *packet_size = (*p++ - 192) << 8;
            *packet_size += *p++ + 192;
            break;
        default:
            /* should probably support more lengths... */
            fprintf(stderr, "Unsupported packet length.\n");
            return -ENOTSUP;
            break;
        }
    }
    /* old format packet length (4.2.1) */
    else {
        printf("Old packet length format found.\n");
        uint8_t length_type = tag & 0x03;
        /* packet tag is in bits 5-2 */
        tag &= 0x3C;
        tag >>= 2;

        switch(length_type) {
        case 0:
            /* one byte length */
            *packet_size = *p++;
            break;
        case 1:
            /* two byte length */
            /* datalen must be at least three bytes */
            if(*datalen < 3)
                goto short_packet;

            *packet_size = *p++ << 8;
            *packet_size |= *p++;
            break;
        case 2:
            /* four byte length */
            /* datalen must be at least five bytes */
            if(*datalen < 5)
                goto short_packet;

            *packet_size = *p++ << 24;
            *packet_size |= *p++ << 16;
            *packet_size |= *p++ << 8;
            *packet_size |= *p++;
            break;
        case 3:
            /* indeterminate length, we do not support this. */
        default:
            fprintf(stderr, "Unsupported data length.\n");
            return -ENOTSUP;
            break;
        }
    }

    printf("Found PGP packet, size %lu.\n", *packet_size);
    newlen -= (p - *data);
    /* do we have enough data for the given size? */
    if(newlen < *packet_size)
        goto short_packet;

    *datalen = newlen;
    *data = p;

    return tag;

short_packet:
    fprintf(stderr, "Packet is not long enough.\n");
    return -EINVAL;
}

int process_packets_from_file(const char *filename)
{
    /* open an fd and send the result to process_packets_from_fd. */
    int ret = 0;
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Could not open %s: %s\n", filename, strerror(errno));
        return -EINVAL;
    }

    ret = process_packets_from_fd(fd);

    close(fd);

    return ret;
}

int process_packets_from_fd(int fd)
{
    /* Read and parse packets from the file given as fd. */
    int ret = 0;
    struct stat stbuf;
    uint64_t filesize;
    uint8_t *buffer;
    FILE *fp;

    fp = fdopen(fd, "rb");
    if(!fp)
        goto error;

    /* find size of file */
    if(fstat(fd, &stbuf) == -1) {
        fclose(fp);
        goto error;
    }

    filesize = stbuf.st_size;
    buffer = malloc(filesize);
    if(!buffer) {
        fclose(fp);
        goto error;
    }

    if(fread(buffer, filesize, 1, fp) == 0) {
        fclose(fp);
        free(buffer);
        goto error;
    }

    ret = process_packets_from_data((const uint8_t*)buffer, filesize);

exit:
    fclose(fp);
    free(buffer);
    return ret;

error:
    fprintf(stderr, "Could not read the given file.\n");
    return -EINVAL;
}

int process_packets_from_data(const uint8_t *data, uint64_t datalen)
{
    /* Read and process packets from the data at data. */
    int ret = 0;
    uint64_t packet_size;
    libsign_signature *sig_ctx = NULL;
    libsign_public_key *pub_ctx = NULL;

    while(datalen) {
        int tag = parse_packet_header(&data, &datalen, &packet_size);
        if(tag < 0) {
            fprintf(stderr, "Could not parse packet header.\n");
            ret = tag;
            goto exit;
        }

        datalen -= packet_size;

        switch(tag) {
        case PGP_TAG_SIGNATURE:
            /* process signature */
            sig_ctx = malloc(sizeof(libsign_signature));
            if(!sig_ctx) {
                fprintf(stderr, "Failed to allocate signature.\n");
                ret = -ENOMEM;
                goto exit;
            }
            ret = process_signature_packet(&data, &packet_size, sig_ctx);
            if(ret < 0) {
                fprintf(stderr, "Could not process signature packet.\n");
                ret = -EINVAL;
                free(sig_ctx);
                goto exit;
            }
            packet_callbacks.signature_parsed(sig_ctx);
            break;
        case PGP_TAG_SECRET_KEY:
            /* process secret key */
            packet_callbacks.secret_key_parsed();
            break;
        case PGP_TAG_PUBLIC_KEY:
            /* process public key */
            pub_ctx = malloc(sizeof(libsign_public_key));
            if(!pub_ctx) {
                fprintf(stderr, "Failed to allocate public key.\n");
                ret = -ENOMEM;
                goto exit;
            }
            ret = process_public_key_packet(&data, &packet_size, pub_ctx);
            if(ret < 0) {
                fprintf(stderr, "Could not process public key packet.\n");
                ret = -EINVAL;
                goto exit;
            }
            packet_callbacks.public_key_parsed(pub_ctx);
            break;
        case PGP_TAG_USERID:
            /* skip for now */
            data += packet_size;
            break;
        case PGP_TAG_PUBLIC_SUBKEY:
            /* skip for now */
            data += packet_size;
            break;
        default:
            fprintf(stderr, "Unhandled packet tag %d.", tag);
            ret = -ENOTSUP;
            goto exit;
        }
    }
exit:
    return ret;
}

void set_callbacks(packet_parsed_callbacks *callbacks)
{
    memcpy(&packet_callbacks, callbacks, sizeof(packet_parsed_callbacks));
}

void dummy_signature_parsed(libsign_signature *ctx)
{
    free(ctx);
}

void dummy_public_key_parsed(libsign_public_key *ctx)
{
    free(ctx);
}

void dummy_fallback()
{

}
