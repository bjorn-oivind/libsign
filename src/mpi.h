#ifndef __LIBSIGN_MPI_H
#define __LIBSIGN_MPI_H

#include <stdint.h>
#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

int mpi_to_mpz(const uint8_t **data, uint32_t *datalen, mpz_t *i);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSIGN_MPI_H */
