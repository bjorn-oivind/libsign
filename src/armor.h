#ifndef __LIBSIGN_ARMOR_H
#define __LIBSIGN_ARMOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int decode_armor(uint8_t *armor_in, uint64_t armor_len, uint8_t **plain_out, uint64_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif // __LIBSIGN_ARMOR_H
