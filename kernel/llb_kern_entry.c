/*
 *  llb_kern_entry.c: LoxiLB Kernel eBPF entry points
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_pdi.h"
#include "../common/llb_dpapi.h"

#include "llb_kern_cdefs.h"
#include "llb_kern_sum.c"
#include "llb_kern_compose.c"
#include "llb_kern_policer.c"
#include "llb_kern_sessfwd.c"
#include "llb_kern_fw.c"
#include "llb_kern_natlbfwd.c"
#include "llb_kern_ct.c"
#include "llb_kern_l3fwd.c"
#include "llb_kern_l2fwd.c"
#include "llb_kern_devif.c"
#include "llb_kern_fcfwd.c"

static int __always_inline
dp_ingress_pkt_main(struct __sk_buff *md, struct xfi *xf)
{
  BPF_TRACE_PRINTK("[ENTRY] start%d", bpf_get_smp_processor_id());

  if (xf->pm.phit & LLB_DP_FC_HIT) {
    dp_parse_depth0(md, xf, 0);
  }

  /* Handle parser results */
  if (xf->pm.pipe_act & LLB_PIPE_REWIRE) {
    return dp_rewire_packet(md, xf);
  } else if (xf->pm.pipe_act & LLB_PIPE_RDR) {
    return dp_redir_packet(md, xf);
  }

  if (xf->pm.pipe_act & LLB_PIPE_PASS ||
      xf->pm.pipe_act & LLB_PIPE_TRAP) {
    xf->pm.rcode |= LLB_PIPE_RC_MPT_PASS;
    return DP_PASS;
  }

  return dp_ingress_slow_main(md, xf);
}

#ifndef LL_TC_EBPF
SEC("xdp_packet_hook")
int  xdp_packet_func(struct xdp_md *ctx)
{
  int z = 0;
  struct xfi *xf;

  BPF_TRACE_PRINTK("[ENTRY] xdp start");

  xf = bpf_map_lookup_elem(&xfis, &z);
  if (!xf) {
    return DP_DROP;
  }
  memset(xf, 0, sizeof *xf);

  dp_parse_depth0(ctx, xf, 1);

#ifdef HAVE_DP_RSS
  if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IP) &&
      xf->l34m.nw_proto == IPPROTO_SCTP) {
      __u32 dcpu;
      __u32 *mcpu;
      __u32 seed = bpf_get_prandom_u32();
      __u32 hash = (__u32)(xf->l34m.saddr[0]) ^
                   ((__u32)(xf->l34m.source)) ^
                   seed;
      dcpu = hash % MAX_REAL_CPUS;
      mcpu = bpf_map_lookup_elem(&live_cpu_map, &z);
      if (mcpu == NULL) {
        return DP_PASS;
      }

      if (dcpu >= *mcpu) {
        dcpu = 0;
      }

      return bpf_redirect_map(&cpu_map, dcpu, 0);
  }
#endif

  return DP_PASS;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
  return dp_ingress_pass_main(ctx);
}

#else

static int __always_inline
tc_packet_func__(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

#ifndef HAVE_DP_FC
  DP_IN_ACCOUNTING(ctx, xf);
#endif

  memset(xf, 0, sizeof(*xf));
  xf->pm.phit |= LLB_DP_FC_HIT;
  xf->pm.tc = 1;

  return dp_ingress_pkt_main(md, xf);
}

SEC("tc_packet_hook0")
int tc_packet_func_fast(struct __sk_buff *md)
{
#ifdef LL_TC_EBPF_EHOOK
  if (DP_LLB_ISTAMPED(md) || DP_LLB_OSTAMPED(md)) {
    DP_LLB_RST_STAMP(md);
    return DP_PASS;
  } else {
    DP_LLB_OSTAMP(md);
  }
#else
  if (DP_LLB_OSTAMPED(md)) {
    return DP_PASS;
  }
  DP_LLB_ISTAMP(md);
#endif

#ifdef HAVE_DP_FC
  struct xfi *xf;

  DP_NEW_FCXF(xf);

  DP_IN_ACCOUNTING(ctx, xf);

  if (md->len > LLB_SKB_FIXUP_LEN) {
    bpf_skb_pull_data(md, LLB_SKB_MIN_DPA_LEN);
  }

  dp_parse_depth0(md, xf, 1);

  return  dp_ingress_fast_main(md, xf);
#else
  return tc_packet_func__(md);
#endif
}

SEC("tc_packet_hook1")
int tc_packet_func(struct __sk_buff *md)
{
  return tc_packet_func__(md);
}

SEC("tc_packet_hook2")
int tc_packet_func_slow(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_ingress_ct_main(md, xf);
}

SEC("tc_packet_hook3")
int tc_packet_func_fw(struct __sk_buff *ctx)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_do_fw_main(ctx, xf);
}

SEC("tc_packet_hook4")
int tc_csum_func1(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  val = dp_sctp_csum(md, xf);
  if (val == DP_DROP || val == DP_PASS) {
    xf->pm.rcode |= LLB_PIPE_RC_CSUM_DRP;
    TRACER_CALL(md, xf);
  }
  return val;
}

SEC("tc_packet_hook5")
int tc_csum_func2(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  val = dp_sctp_csum(md, xf);
  if (val == DP_DROP || val == DP_PASS) {
    xf->pm.rcode |= LLB_PIPE_RC_CSUM_DRP;
    TRACER_CALL(md, xf);
  }
  return val;
}

SEC("tc_packet_hook6")
int tc_slow_unp_func(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  val = dp_unparse_packet_always_slow(md, xf);
  if (val == DP_DROP) {
    xf->pm.rcode |= LLB_PIPE_RC_UNPS_DRP;
    TRACER_CALL(md, xf);
  }
  return val;
}

SEC("tc_packet_hook7")
int tc_packet_func_masq(struct __sk_buff *ctx)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  if (xf->pm.dp_mark & LLB_MARK_NAT) {
    /* Do masquerade */
    dp_do_nat(ctx, xf);
    RETURN_TO_MP();
    /* Not reached */
    return DP_DROP;
  }
  return DP_DROP;
}

#endif
