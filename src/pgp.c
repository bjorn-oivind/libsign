#include <pgp.h>

#define PGP_CRC24_INIT 0xB704CEL
#define PGP_CRC24_POLY 0x1864CFBL

uint32_t pgp_crc24(size_t length, const uint8_t *data)
{
    uint32_t crc = PGP_CRC24_INIT;
    int i;

    while(length--) {
        crc ^= (*data++) << 16;
        for(i = 0; i < 8; i++) {
            crc <<= 1;
            if(crc & 0x1000000)
                crc ^= PGP_CRC24_POLY;
        }
    }

    return crc & 0xFFFFFFL;
}
