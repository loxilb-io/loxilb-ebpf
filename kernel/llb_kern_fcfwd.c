/*
 *  llb_kern_fc.c: LoxiLB kernel cache based forwarding
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

static int  __always_inline
dp_mk_fcv4_key(struct xfi *xf, struct dp_fcv4_key *key)
{
#ifdef HAVE_DP_EXTFC
  memcpy(key->smac, xf->l2m.dl_src, 6);
  memcpy(key->dmac, xf->l2m.dl_dst, 6);
  memcpy(key->in_smac, xf->il2m.dl_src, 6);
  memcpy(key->in_dmac, xf->il2m.dl_dst, 6);
  //key->bd = xf->pm.bd;
#endif

  key->daddr      = xf->l34m.daddr4;
  key->saddr      = xf->l34m.saddr4;
  key->sport      = xf->l34m.source;
  key->dport      = xf->l34m.dest;
  key->l4proto    = xf->l34m.nw_proto;
  key->pad        = 0;
  key->in_port    = 0;

#ifdef HAVE_DP_EXTFC
  key->in_daddr   = xf->il34m.daddr4;
  key->in_saddr   = xf->il34m.saddr4;
  key->in_sport   = xf->il34m.source;
  key->in_dport   = xf->il34m.dest;
  key->in_l4proto = xf->il34m.nw_proto;
#endif

  return 0;
}

static int __always_inline
dp_do_fcv4_lkup(void *ctx, struct xfi *xf)
{
  struct dp_fcv4_key key;
  struct dp_fc_tacts *acts;
  struct dp_fc_tact *ta;
  int ret = 1;
  int z = 0;

  dp_mk_fcv4_key(xf, &key);

  xf->pm.table_id = LL_DP_FCV4_MAP;
  acts = bpf_map_lookup_elem(&fc_v4_map, &key);
  if (!acts) {
    /* xfck - fast-cache key table is maintained so that
     * there is no need to make fcv4 key again in tail-call sections
     */
    BPF_FC_PRINTK("[FCH4] lkup miss");
    bpf_map_update_elem(&xfck, &z, &key, BPF_ANY);
    return 0; 
  }

#ifdef HAVE_DP_FC_TMO
  /* Check timeout */ 
  if (bpf_ktime_get_ns() - acts->its > FC_V4_DPTO) {
    BPF_FC_PRINTK("[FCH4] hto");
    bpf_map_update_elem(&xfck, &z, &key, BPF_ANY);
    bpf_map_delete_elem(&fc_v4_map, &key);
    xf->pm.rcode |= LLB_PIPE_RC_FCTO;
    return 0; 
  }
#endif

  if (acts->ca.ftrap) {
    xf->pm.rcode |= LLB_PIPE_RC_FCBP;
    return 0; 
  }

  xf->pm.phit |= LLB_DP_FC_HIT;
  xf->pm.zone = acts->zone;
  xf->pm.pten = acts->pten;

#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_RM_VXLAN].ca.act_type == DP_SET_RM_VXLAN) {
    BPF_FC_PRINTK("[FCH4] strip-vxlan-act");
    ta = &acts->fcta[DP_SET_RM_VXLAN];
    dp_pipe_set_rm_vx_tun(ctx, xf, &ta->nh_act);
  }
#endif

  if (acts->fcta[DP_SET_SNAT].ca.act_type == DP_SET_SNAT) {
    BPF_FC_PRINTK("[FCH4] snat-act");
    ta = &acts->fcta[DP_SET_SNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      xf->pm.rcode |= LLB_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 1);
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, LLB_NAT_STAT_CID(ta->nat_act.rid, ta->nat_act.aid));
  } else if (acts->fcta[DP_SET_DNAT].ca.act_type == DP_SET_DNAT) {
    BPF_FC_PRINTK("[FCH4] dnat-act");
    ta = &acts->fcta[DP_SET_DNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      xf->pm.rcode |= LLB_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 0);
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, LLB_NAT_STAT_CID(ta->nat_act.rid, ta->nat_act.aid));
  }

#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_RT_TUN_NH].ca.act_type == DP_SET_RT_TUN_NH) {
    ta = &acts->fcta[DP_SET_RT_TUN_NH];
    BPF_FC_PRINTK("[FCH4] tun-nh found");
    dp_pipe_set_l22_tun_nh(ctx, xf, &ta->nh_act);
  } else if (acts->fcta[DP_SET_L3RT_TUN_NH].ca.act_type == DP_SET_L3RT_TUN_NH) {
    BPF_FC_PRINTK("[FCH4] l3-rt-tnh-act");
    ta = &acts->fcta[DP_SET_L3RT_TUN_NH];
    dp_pipe_set_l32_tun_nh(ctx, xf, &ta->nh_act);
  }
#endif

  if (acts->fcta[DP_SET_NEIGH_L2].ca.act_type == DP_SET_NEIGH_L2) {
    BPF_FC_PRINTK("[FCH4] l2-rt-nh-act");
    ta = &acts->fcta[DP_SET_NEIGH_L2];
    dp_do_rt_l2_nh(ctx, xf, &ta->nl2);
  }

#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_NEIGH_VXLAN].ca.act_type == DP_SET_NEIGH_VXLAN) {
    BPF_FC_PRINTK("[FCH4] rt-l2-nh-vxlan-act");
    ta = &acts->fcta[DP_SET_NEIGH_VXLAN];
    dp_do_rt_tun_nh(ctx, xf, LLB_TUN_VXLAN, &ta->ntun);
  }
#endif

  if (acts->fcta[DP_SET_ADD_L2VLAN].ca.act_type == DP_SET_ADD_L2VLAN) {
    BPF_FC_PRINTK("[FCH4] new-l2-vlan-act");
    ta = &acts->fcta[DP_SET_ADD_L2VLAN];
    dp_set_egr_vlan(ctx, xf, ta->l2ov.vlan, ta->l2ov.oport);
  } else if (acts->fcta[DP_SET_RM_L2VLAN].ca.act_type == DP_SET_RM_L2VLAN) {
    BPF_FC_PRINTK("[FCH4] strip-l2-vlan-act");
    ta = &acts->fcta[DP_SET_RM_L2VLAN];
    dp_set_egr_vlan(ctx, xf, 0, ta->l2ov.oport);
  } else if (acts->fcta[DP_SET_TOCP].ca.act_type == DP_SET_TOCP) {
    BPF_FC_PRINTK("[FCH4] to-cp-act");
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else {
    goto slow_pout;
  }

  /* Catch any conditions which need us to go to cp/ct */
  if (xf->pm.l4fin) {
    acts->ca.ftrap = 1;
    goto slow_pout;
  }

  DP_RUN_CT_HELPER(xf);

  if (acts->ca.fwrid != 0) {
    dp_do_map_stats(ctx, xf, LL_DP_FW_STATS_MAP, acts->ca.fwrid);
  }

  dp_do_map_stats(ctx, xf, LL_DP_CT_STATS_MAP, acts->ca.cidx);

  BPF_FC_PRINTK("[FCH4] oport %d",  xf->pm.oport);
 
  xf->pm.oport = acts->ca.oaux; /* Field overloaded as oif */

  return ret;

slow_pout:
  //bpf_map_delete_elem(&fc_v4_map, &key);
  xf->pm.rcode |= LLB_PIPE_RC_FCBP;
  return 0;
}

/*
 * dp_ingress_fast_main - Cache-based fast-path packet forwarding
 * --------------------------------------------------------------
 * This function handles ingress packet processing with a focus on
 * high-speed forwarding using precomputed cache lookups.
 * Instead of performing full packet inspection and policy evaluation
 * for every packet, it leverages cached state to to make
 * near-instant forwarding decisions.
 *
 * Key optimizations:
 * - Bypasses expensive lookups when a cached entry is available.
 * - Reduces per-packet processing latency in the fast path.
 * - Ensures minimal verifier complexity while maintaining efficiency.
 *
 * If a packet does not have a valid cache entry, it falls back to
 * a more detailed processing pipeline for further handling.
 */
static int __always_inline
 dp_ingress_fast_main(void *ctx, struct xfi *xf)
{
  int z = 0;
  int oif;
  __u32 idx = LLB_DP_PKT_SLOW_PGM_ID;
  BPF_FC_PRINTK("[FCHM] Main--");
  if (xf->pm.pipe_act == 0 &&
      xf->l2m.dl_type == bpf_ntohs(ETH_P_IP)) {
    if (dp_do_fcv4_lkup(ctx, xf) == 1) {
      if (xf->pm.pipe_act == LLB_PIPE_RDR) {
        dp_unparse_packet_always(ctx, xf);
        dp_unparse_packet(ctx, xf, 0);
        DP_EG_ACCOUNTING(ctx, xf);
        oif = xf->pm.oport;
        return bpf_redirect(oif, 0);         
      } else if (xf->pm.pipe_act & LLB_PIPE_TRAP) {
        return DP_PASS;
      }
    }
  }

  DP_DO_BUF_FIXUP(ctx, xf);

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);
  bpf_tail_call(ctx, &pgm_tbl, idx);

  TRACER_CALL(ctx, xf);
  return DP_DROP;
}
