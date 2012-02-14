#include "packet.h"
#include "b64/cdecode.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <pgp.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

/* 4.2 */
int parse_packet_header(const uint8_t **data, uint32_t *datalen, uint32_t *packet_size)
{
    int ret = -EINVAL;
    uint8_t tag;
    const uint8_t *p = *data;
    uint32_t newlen = *datalen;
    /* datalen must be at least two bytes */
    if(*datalen < 2)
        goto exit;

    tag = *p++;

    if(!(tag & 0x80))
        goto exit;

    tag &= ~0x80;

    /* is it a new format header? (4.2.2) */
    if(tag & 0x40) {
        tag &= ~0x40;
        if(*p <= 0xbf) {
            /* one byte length (4.2.2.1) */
            *packet_size = *p++;
        }
        else if(*p >= 0xc0 && *p <= 0xdf) {
            /* two byte length (4.2.2.2) */
            /* datalen must be at least three bytes */
            if(*datalen < 3)
                goto exit;
            *packet_size = (*p++ - 192) << 8;
            *packet_size += *p++ + 192;
        }
        else {
            /* should probably support more lengths... */
            ret = -ENOTSUP;
            goto exit;
        }
    }
    /* old format packet length (4.2.1) */
    else {
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
                goto exit;

            *packet_size = *p++ << 8;
            *packet_size |= *p++;
            break;
        case 2:
            /* four byte length */
            /* datalen must be at least five bytes */
            if(*datalen < 5)
                goto exit;

            *packet_size = *p++ << 24;
            *packet_size |= *p++ << 16;
            *packet_size |= *p++ << 8;
            *packet_size |= *p++;
            break;
        case 3:
            /* indeterminate length, we do not support this. */
        default:
            ret = -ENOTSUP;
            goto exit;
            break;
        }
    }

    newlen -= (p - *data);
    /* do we have enough data for the given size? */
    if(newlen < *packet_size)
        goto exit;

    *datalen = newlen;
    *data = p;

    ret = tag;

exit:
    return ret;
}
