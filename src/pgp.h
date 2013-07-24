#ifndef __LIBSIGN_PGP_H
#define __LIBSIGN_PGP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 5.5.2 */
enum pgp_key_version {
    PGP_KEY_VER3    = 3,
    PGP_KEY_VER4    = 4
};

/* 5.2.2, 5.2.3 */
enum pgp_sig_version {
    PGP_SIG_VER3    = 3,
    PGP_SIG_VER4    = 4
};

/* 9.1 */
enum pgp_public_key_algorithm {
    PGP_RSA                     = 1,
    PGP_RSA_ENCRYPT_ONLY        = 2,
    PGP_RSA_SIGN_ONLY           = 3,
    PGP_ELGAMAL_ENCRYPT_ONLY    = 16,
    PGP_DSA                     = 17
};

/* 9.4 */
enum pgp_hash_algorithm {
    PGP_MD5         = 1,
    PGP_SHA1        = 2,
    PGP_RIPEMD160   = 3,
    PGP_SHA256      = 8,
    PGP_SHA384      = 9,
    PGP_SHA512      = 10,
    PGP_SHA224      = 11
};

/* 5.2.1 */
enum pgp_signature_type {
    PGP_SIG_BINARY_DOCUMENT             = 0x00,
    PGP_SIG_CANONICAL_TEXT              = 0x01,
    PGP_SIG_STANDALONE                  = 0x02,
    PGP_SIG_GENERIC_CERT                = 0x10,
    PGP_SIG_PERSONA_CERT                = 0x11,
    PGP_SIG_CASUAL_CERT                 = 0x12,
    PGP_SIG_POSITIVE_CERT               = 0x13,
    PGP_SIG_SUBKEY_BINDING              = 0x18,
    PGP_SIG_PRIMARY_KEY_BINDING         = 0x19,
    PGP_SIG_KEY_DIRECT                  = 0x1F,
    PGP_SIG_KEY_REVOCATION              = 0x20,
    PGP_SIG_SUBKEY_REVOCATION           = 0x28,
    PGP_SIG_CERT_REVOCATION             = 0x30,
    PGP_SIG_TIMESTAMP                   = 0x40,
    PGP_SIG_THIRD_PARTY_CONFIRMATION    = 0x50
};

/* 4.3 */
enum pgp_packet_tag {
    PGP_TAG_RESERVED                            = 0,
    PGP_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY    = 1,
    PGP_TAG_SIGNATURE                           = 2,
    PGP_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY = 3,
    PGP_TAG_ONE_PASS_SIGNATURE                  = 4,
    PGP_TAG_SECRET_KEY                          = 5,
    PGP_TAG_PUBLIC_KEY                          = 6,
    PGP_TAG_SECRET_SUBKEY                       = 7,
    PGP_TAG_COMPRESSED_DATA                     = 8,
    PGP_TAG_SYMMETRICALLY_ENCRYPTED_DATA        = 9,
    PGP_TAG_MARKER_PACKET                       = 10,
    PGP_TAG_LITERAL_DATA                        = 11,
    PGP_TAG_TRUST                               = 12,
    PGP_TAG_USERID                              = 13,
    PGP_TAG_PUBLIC_SUBKEY                       = 14,
    PGP_TAG_USER_ATTRIBUTE                      = 15,
    PGP_TAG_SYMMETRICALLY_ENCRYPTED_SIGNED_DATA = 18,
    PGP_TAG_MODIFICATION_DETECTION_CODE         = 19
};

/* 6.1 */
uint32_t pgp_crc24(size_t length, const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_PGP_H */
