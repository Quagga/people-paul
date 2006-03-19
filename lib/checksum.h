extern uint16_t in_cksum(void *, int);

/* the guts of in_cksum, to facilitate cksum on non-contigious data */
extern void in_cksum_accumulate (uint32_t *, void *, int);
extern uint16_t in_cksum_finish (uint32_t);
