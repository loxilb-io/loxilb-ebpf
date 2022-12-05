/*
 *  llb_kern_sum.c: LoxiLB Kernel in-eBPF checksums 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_TCALL (400)

#define RETURN_TO_MP() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID)

static void __always_inline
dp_ipv4_new_csum(struct iphdr *iph)
{
    __u16 *iph16 = (__u16 *)iph;
    __u32 csum;
    int i;

    iph->check = 0;

#pragma clang loop unroll(full)
    for (i = 0, csum = 0; i < sizeof(*iph) >> 1; i++)
        csum += *iph16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
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

static void __always_inline
dp_sctp_csum(void *ctx, struct xfi *xf)
{
  int loop = 0;
  int off;
  int rlen;
  __u32 crc = 0xffffffff;
  __u8 pb;

  xf->km.key[0] == ~xf->km.key[0]; // Next tail-call
  off = xf->km.key[1];
  len = xf->km.key[2];
  if (off) {
    crc = *(__u32 *)&xf->km.key[3];
  }
  
  for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL; loop++) {
    while (rlen--) {
      ret = dp_pktbuf_read(ctx, off, &pb, sizeof(pb));
      if (ret < 0) {
        goto drop;
      }
      idx =(crc ^ pb) & 0xff;
      tbval = get_crc32c_map(idx);
      crc = tbval ^ (crc >> 8);
      off++;
    }
    if (rlen <= 0) {
      /* TODO Update crc in sctp */
      /* TODO Update check in IP */
      /* TODO Reset any flag which indicates further sctp processing */
      /* Done */
      RETURN_TO_MP();    
    }
  }

  /* Update state-variables */
  xf->km.key[1] = off;
  xf->km.key[2] = len;
  *(__u32 *)&xf->km.key[3] = crc;

  /* TODO Jump to next helper section for checksum */
 
  return 0;
drop:
  /* Something went wrong here */
  return DP_DROP;
}
