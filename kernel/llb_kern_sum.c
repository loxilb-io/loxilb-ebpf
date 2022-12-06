/*
 *  llb_kern_sum.c: LoxiLB Kernel in-eBPF checksums 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_TCALL (256)

#define RETURN_TO_MP_OUT()                       \
do {                                             \
  xf->pm.phit |= LLB_DP_RES_HIT;                 \
  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);\
} while(0)

#define TCALL_CRC1() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID1)
#define TCALL_CRC2() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID2)

static int __always_inline
dp_sctp_csum_tcall(void *ctx,  struct xfi *xf)
{
  __u32 crc = 0xffffffff;

   /* Init state-variables */
  xf->km.skey[0] = 0;
  xf->km.skey[1] = xf->pm.l4_off;
  xf->km.skey[2] = xf->pm.py_bytes - xf->pm.l4_off;
  *(__u32 *)&xf->km.skey[3] = crc;
  TCALL_CRC1();
  return DP_DROP;
}

static __u32 __always_inline
get_crc32c_map(__u32 off)
{
  __u32 *val;

  val = bpf_map_lookup_elem(&crc32c_map, &off); 
  if (!val) {
    /* Not Reached */
    return 0;
  }

  return *val;
}

static int __always_inline
dp_sctp_csum(void *ctx, struct xfi *xf)
{
  int ret;
  int off;
  int rlen;
  int tcall;
  __u32 tbval;
  __u8 pb;
  int loop = 0;
  __u32 crc = 0xffffffff;

  tcall = ~xf->km.skey[0]; // Next tail-call
  off = xf->km.skey[1];
  rlen = xf->km.skey[2];
  if (off) {
    crc = *(__u32 *)&xf->km.skey[3];
  }

  for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL; loop++) {
      __u8 idx;
      if (rlen > 0) {
        ret = dp_pktbuf_read(ctx, off, &pb, sizeof(pb));
        if (ret < 0) {
          goto drop;
        }
        idx =(crc ^ pb) & 0xff;
        tbval = get_crc32c_map(idx);
        crc = tbval ^ (crc >> 8);
        off++;
        rlen--;
    } else break;
  }
  if (rlen <= 0) {
     /* Update crc in sctp */
      /* Reset any flag which indicates further sctp processing */
      if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
        void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
        struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
        int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum);
        __be32 csum;

        if (sctp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return DP_DROP;
        }
        csum = bpf_htonl(crc);
        dp_pktbuf_write(ctx, sctp_csum_off, &csum , sizeof(csum), 0); 
        xf->pm.nf &= ~LLB_NAT_SRC;
        xf->pm.nf &= ~LLB_NAT_DST;
      }
        
      RETURN_TO_MP_OUT();
  }

  /* Update state-variables */
  xf->km.skey[0] = tcall;
  xf->km.skey[1] = off;
  xf->km.skey[2] = rlen;
  *(__u32 *)&xf->km.skey[3] = crc;

  /* Jump to next helper section for checksum */
  if (tcall) {
    TCALL_CRC2();
  } else {
    TCALL_CRC1();
  }
 
drop:
  /* Something went wrong here */
  return DP_DROP;
}
