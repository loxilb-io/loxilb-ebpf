/*
 *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

static int __always_inline
dp_do_fw4_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  __u32 idx = 0;
  int i = 0;
  struct dp_fwv4_ent *fwe;
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

  idx = xf->pm.fw_lid;

  for (i = 0; i < 10; i++) {

    fwe = bpf_map_lookup_elem(&fw_v4_map, &idx);
    if (!fwe) {
      LL_DBG_PRINTK("[FW4] miss");
      return 0;
    }

    idx++;

    if ((key.daddr & fwe->m.daddr) == fwe->v.daddr &&
        (key.saddr & fwe->m.saddr) == fwe->v.saddr &&
        (key.sport & fwe->m.sport) == fwe->v.sport &&
        (key.dport & fwe->m.dport) == fwe->v.dport &&
        (key.l4proto & fwe->m.l4proto) == fwe->v.l4proto) {

      xf->pm.fw_lid = 0;
      break;
    }
  }

  xf->pm.phit |= LLB_DP_FW_HIT;

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

    dp_pipe_set_nat(ctx, xf, na, act->ca.act_type == DP_SET_SNAT ? 1: 0);
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
}
