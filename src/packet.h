#ifndef __LIBSIGN_PACKET_H
#define __LIBSIGN_PACKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int parse_packet_header(const uint8_t **data, uint32_t *datalen, uint32_t *packet_size);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PACKET_H */
