/*
 *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: GPL-2.0
 */

static int __always_inline
dp_do_fw4_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  __u32 idx = 0;
  struct dp_ctv4_key key;
  struct dp_aclv4_tact *act;
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  key.daddr = xf->l3m.ip.daddr;
  key.saddr = xf->l3m.ip.saddr;
  key.sport = xf->l3m.source;
  key.dport = xf->l3m.dest;
  key.l4proto = xf->l3m.nw_proto;
  key.zone = xf->pm.zone;
  key.r = 0;

  LL_DBG_PRINTK("[FW4] -- Lookup\n");
  LL_DBG_PRINTK("[FW4] key-sz %d\n", sizeof(key));
  LL_DBG_PRINTK("[FW4] daddr %x\n", key.daddr);
  LL_DBG_PRINTK("[FW4] saddr %d\n", key.saddr);
  LL_DBG_PRINTK("[FW4] sport %d\n", key.sport);
  LL_DBG_PRINTK("[FW4] dport %d\n", key.dport);
  LL_DBG_PRINTK("[FW4] l4proto %d\n", key.l4proto);

  xf->pm.table_id = LL_DP_FW4_MAP;

  act = bpf_map_lookup_elem(&fw_v4_map, &idx);
  if (!act) {
    LL_DBG_PRINTK("[ACL4] miss");
    goto ct_trk;
  }

  xf->pm.phit |= LLB_DP_ACL_HIT;
  act->lts = bpf_ktime_get_ns();

#ifdef HAVE_DP_FC
  fa->ca.cidx = act->ca.cidx;
#endif

  if (act->ca.act_type == DP_SET_DO_CT) {
    goto ct_trk;
  } else if (act->ca.act_type == DP_SET_NOP) {
    struct dp_rdr_act *ar = &act->port_act;
    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;

    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_SNAT || 
             act->ca.act_type == DP_SET_DNAT) {
    struct dp_nat_act *na;
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[
                                  act->ca.act_type == DP_SET_SNAT ?
                                  DP_SET_SNAT : DP_SET_DNAT];
    ta->ca.act_type = act->ca.act_type;
    memcpy(&ta->nat_act,  &act->nat_act, sizeof(act->nat_act));
#endif

    na = &act->nat_act;

    if (xf->pm.l4fin) {
      na->fr = 1;
    }

    dp_pipe_set_nat(ctx, xf, na, act->ca.act_type == DP_SET_SNAT ? 1: 0);
    dp_do_map_stats(ctx, xf, LL_DP_NAT4_STATS_MAP, na->rid);

    if (na->fr == 1 || na->doct) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_TOCP) {
    /*LLBS_PPLN_TRAP(xf);*/
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_ACL_MISS);
  } else if (act->ca.act_type == DP_SET_SESS_FWD_ACT) {
    struct dp_sess_act *pa = &act->pdr_sess_act; 
    xf->pm.sess_id = pa->sess_id;
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROP(xf);
  }

  dp_do_map_stats(ctx, xf, LL_DP_ACLV4_STATS_MAP, act->ca.cidx);
#if 0
  /* Note that this might result in consistency problems 
   * between packet and byte counts at times but this should be 
   * better than holding bpf-spinlock 
   */
  lock_xadd(&act->ctd.pb.bytes, xf->pm.l3_len);
  lock_xadd(&act->ctd.pb.packets, 1);
#endif

  return 0;

ct_trk:
  return dp_tail_call(ctx, xf, fa_, LLB_DP_CT_PGM_ID);
}

static void __always_inline
dp_do_ipv4_fwd(void *ctx,  struct xfi *xf, void *fa_)
{
  if (xf->tm.tunnel_id == 0 ||  xf->tm.tun_type != LLB_TUN_GTP) {
    dp_do_sess4_lkup(ctx, xf);
  }

  if (xf->pm.phit & LLB_DP_TMAC_HIT) {

    /* If some pipeline block already set a redirect before this,
     * we honor this and dont do further l3 processing 
     */
    if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {
      dp_do_rtv4_lkup(ctx, xf, fa_);
    }
  }
}

static int __always_inline
dp_ing_ipv4(void *ctx,  struct xfi *xf, void *fa_)
{
  if (xf->tm.tunnel_id && xf->tm.tun_type == LLB_TUN_GTP) {
    dp_do_sess4_lkup(ctx, xf);
  }
  dp_do_aclv4_lkup(ctx, xf, fa_);
  dp_do_ipv4_fwd(ctx, xf, fa_);

  return 0;
}
