#ifndef __LIBSIGN_MPI_H
#define __LIBSIGN_MPI_H

#include <nettle/bignum.h>

#ifdef __cplusplus
extern "C" {
#endif

int mpi_to_mpz(const uint8_t **data, uint64_t *uint64_t, mpz_t *i);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_MPI_H */
