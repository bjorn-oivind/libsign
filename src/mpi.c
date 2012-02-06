#include "mpi.h"

#include <errno.h>
#include <stdio.h>

/* 3.2 */
int mpi_to_mpz(const uint8_t **data, uint32_t *datalen, mpz_t *i)
{
    /* the MPI used in PGP shall:
        1) start with a two octet big-endian number denoting
           the length of the integer in bits. Note that this
           only counts from the first enabled bit.
        2) be followed by the number in big-endian.
        3) the total size of the MPI (bitlength included) in bytes
           shall be ((MPI.length + 7) / 8) + 2. */
    int ret = 0;
    const uint8_t *p;
    uint32_t bitlen, bytelen, tmplen = *datalen;
    /* we must have at least two bytes to read. */
    if(tmplen < 2) {
        fprintf(stderr, "Invalid MPI found.\n");
        ret = -EINVAL;
        goto exit;
    }

    p = *data;
    bitlen = (*p++ << 8);
    bitlen |= *p++;
    tmplen -= 2;
    /* don't include the header. */
    bytelen = (bitlen + 7) / 8;

    /* do we have enough data to read? */
    if(tmplen < bytelen) {
        fprintf(stderr, "Invalid MPI length.\n");
        ret = -EINVAL;
        goto exit;
    }

    mpz_import(*i, bytelen, 1, 1, 1, 0, p);
    p += bytelen;
    *datalen = tmplen;
    *data = p;
exit:
    return ret;
}
