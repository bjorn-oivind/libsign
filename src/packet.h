#ifndef __LIBSIGN_PACKET_H
#define __LIBSIGN_PACKET_H

#include "signature.h"
#include "public_key.h"

#include <stdint.h>
#include <stdio.h>

#include <nettle/pgp.h>
#include <nettle/bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

struct packet_parsed_callbacks
{
    void (*signature_parsed)(libsign_signature*);
    void (*secret_key_parsed)();
    void (*public_key_parsed)(libsign_public_key*);
} typedef packet_parsed_callbacks;

int parse_packet_header(const uint8_t **data, uint64_t *datalen, uint64_t *packet_size);
int process_armored_packets_from_file(const char *filename);
int process_armored_packets_from_fd(int fd);
int process_armored_packets_from_data(const uint8_t *data, uint64_t datalen);
int process_packets_from_file(const char *filename);
int process_packets_from_fd(int fd);
int process_packets_from_data(const uint8_t *data, uint64_t datalen);
void set_callbacks(packet_parsed_callbacks *callbacks);

void dummy_signature_parsed(libsign_signature *ctx);
void dummy_public_key_parsed(libsign_public_key *ctx);
void dummy_fallback();

static packet_parsed_callbacks packet_callbacks = {
    .signature_parsed = &dummy_signature_parsed,
    .secret_key_parsed = &dummy_fallback,
    .public_key_parsed = &dummy_public_key_parsed,
};

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PACKET_H */
