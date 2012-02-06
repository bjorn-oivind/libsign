#ifndef __LIBSIGN_PACKET_H
#define __LIBSIGN_PACKET_H

#include "signature.h"
#include "public_key.h"

#include <stdint.h>
#include <stdio.h>

#include <pgp.h>
#include <bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

int parse_packet_header(const uint8_t **data, uint64_t *datalen, uint64_t *packet_size);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PACKET_H */
