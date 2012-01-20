#ifndef __LIBSIGN_ARMOR_H
#define __LIBSIGN_ARMOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int decode_armor(uint8_t **data, uint64_t *datalen);

#ifdef __cplusplus
}
#endif

#endif // __LIBSIGN_ARMOR_H
