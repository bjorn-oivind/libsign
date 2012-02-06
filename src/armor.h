#ifndef __LIBSIGN_ARMOR_H
#define __LIBSIGN_ARMOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int decode_armor(const uint8_t *armor_in, uint32_t armor_len, uint8_t **plain_out,
                 uint32_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif // __LIBSIGN_ARMOR_H
