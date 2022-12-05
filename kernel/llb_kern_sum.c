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


static void __always_inline
dp_sctp_csum(void *ctx, struct xfi *xf)
{
  int loop = 0;
  int off;
  int rlen;

  xf->km.key[0] == ~xf->km.key[0];
  off = xf->km.key[1];
  len = xf->km.key[2];
  
  for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL; loop++) {
  }
}
