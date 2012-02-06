#include "armor.h"
#include "b64/cdecode.h"

#include <errno.h>
#include <stdlib.h>
#include <pgp.h>

int decode_armor(const uint8_t *armor_in, uint64_t armor_len, uint8_t **plain_out,
                 uint64_t *plain_len)
{
    int ret = -EINVAL;
    const uint8_t *armor_start, *crc_start;
    uint8_t *pgp_plain;
    uint32_t actual_crc24, expected_crc24, crc_plain;
    uint64_t i, encoded_armor_len, plain_armor_len;
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
    while(i++ < armor_len-1) {
        if(armor_in[i] == '\n' && armor_in[i-1] == '\n')
            break;
    }
    /* did we find it? */
    if(i == armor_len)
        goto exit;

    armor_start = armor_in + i;

    /* find the armor checksum and encrypted packet length */
    i = armor_len;
    while(--i) {
        if(armor_in[i] == '=')
            break;
    }
    /* did we find it? */
    if(!i)
        goto exit;

    crc_start = armor_in + i;
    encoded_armor_len = crc_start - armor_start;

    /* do we have enough data for the CRC too?
       CRC is 5 characters long ('=' and CRC) - 3 octets - 24 bits */
    if(encoded_armor_len + 5 > armor_len)
        goto exit;

    /* allocate buffers for plaintext (this is slightly bigger
       than strictly necessary, but will be realloc'ed) */
    pgp_plain = malloc(encoded_armor_len);
    if(!pgp_plain) {
        ret = -ENOMEM;
        goto exit;
    }

    /* decode the data */
    base64_init_decodestate(&state);
    plain_armor_len = base64_decode_block((char*)armor_start, encoded_armor_len, (char*)pgp_plain, &state);

    /* give back the memory we don't need */
    pgp_plain = realloc(pgp_plain, plain_armor_len);
    if(!pgp_plain)
        goto free_pgp;

    actual_crc24 = nettle_pgp_crc24(plain_armor_len, pgp_plain);

    /* decode the CRC */
    base64_init_decodestate(&state);
    /* ignore '='... */
    base64_decode_block((char*)crc_start + 1, 4, (char*)&crc_plain, &state);

    expected_crc24 = (crc_plain & 0xff0000) >> 16 |
                       (crc_plain & 0x0000ff) << 16 |
                       (crc_plain & 0x00ff00);

    if(actual_crc24 != expected_crc24)
        goto free_pgp;

    *plain_out = pgp_plain;
    *plain_len = plain_armor_len;

    return 0;

free_pgp:
    free(pgp_plain);
exit:
    return ret;
}
