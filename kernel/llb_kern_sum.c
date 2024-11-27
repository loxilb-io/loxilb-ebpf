/*
 *  llb_kern_sum.c: LoxiLB Kernel in-eBPF checksums 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_TCALL (76)
#define PBUF_STACK_SZ (32)

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
  int rlen;
  __u8 tcall;
  __u32 tbval;
  __u8 pb;
  __u8 idx;
  __u16 off = 0;
  int loop = 0;
  __u32 crc = 0xffffffff;
  __u8 pbuf[PBUF_STACK_SZ];

  xf->pm.phit |= LLB_DP_CSUM_HIT;

  tcall = ~xf->km.skey[0]; // Next tail-call
  off = *(__u16 *)&xf->km.skey[2];
  rlen = *(__u16 *)&xf->km.skey[4];
  if (off) {
    crc = *(__u32 *)&xf->km.skey[8];
  }

  for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL && rlen > 0 && rlen >= PBUF_STACK_SZ; loop++) {
    int ret = dp_pktbuf_read(ctx, off, pbuf, PBUF_STACK_SZ);
    if (ret < 0) {
      goto drop;
    }

    for (int i = 0; i < PBUF_STACK_SZ; i++) {
      pb = pbuf[i];
      idx =(crc ^ pb) & 0xff;
      tbval = get_crc32c_map(idx);
      crc = tbval ^ (crc >> 8);
    }
    off += PBUF_STACK_SZ;
    rlen -= PBUF_STACK_SZ;
  }

  for (int i = 0; i < PBUF_STACK_SZ && i < rlen && loop < DP_MAX_LOOPS_PER_TCALL; i++) {
    int ret = dp_pktbuf_read(ctx, off, pbuf, 1);
    if (ret < 0) {
      goto drop;
    }

    pb = pbuf[0];
    idx =(crc ^ pb) & 0xff;
    tbval = get_crc32c_map(idx);
    crc = tbval ^ (crc >> 8);
    off++;
    rlen--;
  }

  if (rlen <= 0) {
    /*
     * Update crc in sctp. Reset any flag which indicates
     * further sctp processing
     */
      if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
        void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
        struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
        __u16 sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum);
        __be32 csum;

        if (sctp + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCS_ERR);
          return DP_DROP;
        }
        //csum = bpf_htonl(crc ^ 0xffffffff);
        csum = (crc ^ 0xffffffff);
        dp_pktbuf_write(ctx, sctp_csum_off, &csum , sizeof(csum), 0); 
        xf->pm.nf = 0;
        xf->pm.nfc = 1;

        DP_LLB_SET_CRC_HINT(ctx, csum);
        DP_LLB_SET_CRC_OFF(ctx, (sctp_csum_off<<16));
      }
        
      RETURN_TO_MP_OUT(ctx);
  }

  /* Update state-variables */
  xf->km.skey[0] = tcall;
  *(__u16 *)&xf->km.skey[2] = off;
  *(__u16 *)&xf->km.skey[4] = rlen;
  *(__u32 *)&xf->km.skey[8] = crc;

  /* Jump to next helper section for checksum */
  if (tcall) {
    TCALL_CRC2();
  } else {
    TCALL_CRC1();
  }

  bpf_printk("Too many tcalls");
  xf->pm.rcode |= LLB_PIPE_RC_TCALL_ERR;
 
drop:
  /* Something went wrong here */
  xf->pm.rcode |= LLB_PIPE_RC_PLCS_ERR;
  return DP_DROP;
}
