/*
 * Checksum routine for Internet Protocol family headers (C Version).
 *
 * Refer to "Computing the Internet Checksum" by R. Braden, D. Borman and
 * C. Partridge, Computer Communication Review, Vol. 19, No. 2, April 1989,
 * pp. 86-101, for additional details on computing this checksum.
 */

#include <zebra.h>
#include "checksum.h"

void
in_cksum_accumulate (uint32_t *sum, void *parg, int nbytes)
{
  uint16_t oddbyte, *ptr = parg;
  
  while (nbytes > 1)
    {
      *sum += *ptr++;
      nbytes -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1)
    {
      oddbyte = 0;		/* make sure top half is zero */
      *((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
      *sum += oddbyte;
    }
}

uint16_t
in_cksum_finish (uint32_t sum)
{
  uint16_t answer;
  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */

  sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
  sum += (sum >> 16);			/* add carry */
  answer = ~sum;		/* ones-complement, then truncate to 16 bits */
  return(answer);
}

/* One pass internet checksum of contigious data */
uint16_t 	/* return checksum */
in_cksum(void *parg, int nbytes)
{
	uint16_t *ptr = parg;
	register uint32_t	sum;
	uint16_t		oddbyte;
	register uint16_t	answer;
	
	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

				/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return(answer);
}
