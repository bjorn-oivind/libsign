#include "armor.h"
#include "b64/cdecode.h"

#include <errno.h>
#include <stdlib.h>
#include <nettle/pgp.h>

int decode_armor(uint8_t **data, uint64_t *datalen)
{
    int i, ret = -EINVAL;
    const uint8_t *armor_start, *crc_start;
    uint8_t *pgp_plain, *crc_plain;
    uint32_t actual_crc24, expected_crc24, encoded_crc_len, plain_crc_len;
    uint64_t encoded_armor_len, plain_armor_len;
    base64_decodestate state;

    /* (6.2) ASCII armor shall be the concatenation of the following data:
      - armor header line
      - armor headers
      - a blank (zero-length, newline only) line
      - the ascii armored data
      - the armor checksum
      - the armor tail */

    /* find the start of the armor */
    i = 1;
    while(i++ < *datalen-1) {
        if((*data)[i] == '\n' && (*data)[i-1] == '\n')
            break;
    }
    /* did we find it? */
    if(i == *datalen)
        goto exit;

    armor_start = *data + i;

    /* find the armor checksum and encrypted packet length */
    i = *datalen;
    while(--i) {
        if((*data)[i] == '=')
            break;
    }
    /* did we find it? */
    if(!i)
        goto exit;

    crc_start = *data + i;
    encoded_armor_len = crc_start - armor_start;

    /* how long is the CRC? */
    i = 0;
    while(i++ < crc_start - *data) {
        if(crc_start[i] == '\n')
            break;
    }
    /* did we find it? */
    if(i == crc_start - *data)
        goto exit;

    encoded_crc_len = i;

    /* allocate buffers for plaintexts (these are slightly bigger
       than strictly necessary, but will be realloc'ed) */
    pgp_plain = malloc(encoded_armor_len);
    if(!pgp_plain) {
        ret = -ENOMEM;
        goto exit;
    }

    crc_plain = malloc(encoded_crc_len);
    if(!crc_plain) {
        ret = -ENOMEM;
        goto free_pgp;
    }

    /* decode the data */
    base64_init_decodestate(&state);
    plain_armor_len = base64_decode_block((char*)armor_start, encoded_armor_len, (char*)pgp_plain, &state);

    /* give back the memory we don't need */
    pgp_plain = realloc(pgp_plain, plain_armor_len);
    if(!pgp_plain)
        goto free_crc;

    actual_crc24 = nettle_pgp_crc24(plain_armor_len, pgp_plain);

    /* decode the CRC */
    base64_init_decodestate(&state);
    plain_crc_len = base64_decode_block((char*)crc_start, encoded_crc_len, (char*)crc_plain, &state);

    /* make sure the crc is big enough */
    if(plain_crc_len < 3)
        goto free_crc;

    expected_crc24 = crc_plain[0] << 16 | crc_plain[1] << 8 | crc_plain[2];

    if(actual_crc24 != expected_crc24)
        goto free_crc;

    free(*data);
    free(crc_plain);
    *data = pgp_plain;
    *datalen = plain_armor_len;

    return 0;

free_crc:
    free(crc_plain);
free_pgp:
    free(pgp_plain);
exit:
    return ret;
}
