/*
 *  llb_kern_l2fwd.c: LoxiLB kernel eBPF L2 forwarder Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
static int __always_inline
dp_do_smac_lkup(void *ctx, struct xfi *xf, void *fc)
{
  struct dp_smac_key key;
  struct dp_smac_tact *sma;

  if (xf->l2m.vlan[0] == 0) {
    return 0;
  }

  memcpy(key.smac, xf->l2m.dl_src, 6);
  key.bd = xf->pm.bd;

  xf->pm.table_id = LL_DP_SMAC_MAP;

  sma = bpf_map_lookup_elem(&smac_map, &key);
  if (!sma) {
    /* Default action */
    BPF_DBG_PRINTK("[SMAC] lkup miss");
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_NOSMAC);
    return 0;
  }

  xf->pm.phit |= LLB_DP_SMAC_HIT;
  BPF_TRACE_PRINTK("[SMAC] action %d", sma->ca.act_type);

  if (sma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (sma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else if (sma->ca.act_type == DP_SET_NOP) {
    /* Nothing to do */
    return 0;
  } else {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  return 0;
}

static int __always_inline
dp_pipe_set_l22_tun_nh(void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)
{
  xf->pm.nh_num = rnh->nh_num[0];

  /*
   * We do not set out_bd here. After NH lookup match is
   * found and packet tunnel insertion is done, BD is set accordingly
   */
  /*xf->pm.bd = rnh->bd;*/
  xf->tm.new_tunnel_id = rnh->tid;
  return 0;
}

static int __always_inline
dp_pipe_set_rm_vx_tun(void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)
{
  xf->pm.phit &= ~LLB_DP_TMAC_HIT;
  xf->pm.bd = rnh->bd;

  return dp_pop_outer_metadata(ctx, xf, 1);
}

static int __always_inline
__dp_do_tmac_lkup(void *ctx, struct xfi *xf,
                  int tun_lkup, void *fa_)
{
  struct dp_tmac_key key;
  struct dp_tmac_tact *tma;
#ifdef HAVE_DP_EXTFC
  struct dp_fc_tacts *fa = fa_;
#endif

  memcpy(key.mac, xf->l2m.dl_dst, 6);
  key.pad  = 0;
  if (tun_lkup) {
    key.tunnel_id = xf->tm.tunnel_id;
    key.tun_type = xf->tm.tun_type;
  } else {
    key.tunnel_id = 0;
    key.tun_type  = 0;
  }

  xf->pm.table_id = LL_DP_TMAC_MAP;

  tma = bpf_map_lookup_elem(&tmac_map, &key);
  if (!tma) {
    /* No L3 lookup */
    BPF_TRACE_PRINTK("[TMAC] lkup failed");
    return 0;
  }

  xf->pm.phit |= LLB_DP_TMAC_HIT;
  BPF_TRACE_PRINTK("[TMAC] action %d %d", tma->ca.act_type, tma->ca.cidx);

  if (tma->ca.cidx != 0) {
    dp_do_map_stats(ctx, xf, LL_DP_TMAC_STATS_MAP, tma->ca.cidx);
  }

  if (tma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (tma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else if (tma->ca.act_type == DP_SET_RT_TUN_NH) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_RT_TUN_NH];
    ta->ca.act_type = DP_SET_RT_TUN_NH;
    memcpy(&ta->nh_act,  &tma->rt_nh, sizeof(tma->rt_nh));
#endif
    xf->pm.phit &= ~LLB_DP_TMAC_HIT;
    return dp_pipe_set_l22_tun_nh(ctx, xf, &tma->rt_nh);
  } else if (tma->ca.act_type == DP_SET_L3_EN) {
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else if (tma->ca.act_type == DP_SET_RM_VXLAN) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_RM_VXLAN];
    ta->ca.act_type = DP_SET_RM_VXLAN;
    memcpy(&ta->nh_act,  &tma->rt_nh, sizeof(tma->rt_nh));
#endif
    return dp_pipe_set_rm_vx_tun(ctx, xf, &tma->rt_nh);
  }

  return 0;
}

static int __always_inline
dp_do_tmac_lkup(void *ctx, struct xfi *xf, void *fa)
{
  return __dp_do_tmac_lkup(ctx, xf, 0, fa);
}

static int __always_inline
dp_do_tun_lkup(void *ctx, struct xfi *xf, void *fa)
{
  if (xf->tm.tunnel_id != 0) {
    return __dp_do_tmac_lkup(ctx, xf, 1, fa);
  }
  return 0;
}

static int __always_inline
dp_set_egr_vlan(void *ctx, struct xfi *xf,
                __u16 vlan, __u16 oport)
{
  LLBS_PPLN_RDR(xf);
  xf->pm.oport = oport;
  xf->pm.bd = vlan;
  return 0;
}

static int __always_inline
dp_do_dmac_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_dmac_key key;
  struct dp_dmac_tact *dma;
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  memcpy(key.dmac, xf->pm.lkup_dmac, 6);
  key.bd = xf->pm.bd;
  xf->pm.table_id = LL_DP_DMAC_MAP;

  dma = bpf_map_lookup_elem(&dmac_map, &key);
  if (!dma) {
    /* No DMAC lookup */
    BPF_DBG_PRINTK("[DMAC] not found");
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_NODMAC);
    return 0;
  }

  xf->pm.phit |= LLB_DP_DMAC_HIT;
  BPF_TRACE_PRINTK("[DMAC] action %d pipe %d",
                  dma->ca.act_type, xf->pm.pipe_act);

  if (dma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (dma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else if (dma->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ra = &dma->port_act;

    LLBS_PPLN_RDR(xf);
    xf->pm.oport = ra->oport;
    return 0;
  } else if (dma->ca.act_type == DP_SET_ADD_L2VLAN || 
             dma->ca.act_type == DP_SET_RM_L2VLAN) {
    struct dp_l2vlan_act *va = &dma->vlan_act;
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[
                          dma->ca.act_type == DP_SET_ADD_L2VLAN ?
                          DP_SET_ADD_L2VLAN : DP_SET_RM_L2VLAN];
    ta->ca.act_type = dma->ca.act_type;
    memcpy(&ta->l2ov,  va, sizeof(*va));
#endif
    return dp_set_egr_vlan(ctx, xf, 
                    dma->ca.act_type == DP_SET_RM_L2VLAN ?
                    0 : va->vlan, va->oport);
  }

  return 0;
}

static int __always_inline
dp_do_rt_l2_nh(void *ctx, struct xfi *xf,
               struct dp_rt_l2nh_act *nl2)
{
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;
 
  return nl2->rnh_num;
}

static int __always_inline
dp_do_rt_tun_nh(void *ctx, struct xfi *xf, __u32 tun_type,
                struct dp_rt_tunnh_act *ntun)
{
  struct dp_rt_l2nh_act *nl2;

  xf->tm.tun_rip = ntun->l3t.rip;
  xf->tm.tun_sip = ntun->l3t.sip;
  xf->tm.new_tunnel_id = ntun->l3t.tid;
  xf->tm.tun_type = tun_type;

  if (tun_type == LLB_TUN_VXLAN) {
    memcpy(&xf->il2m, &xf->l2m, sizeof(xf->l2m));
    xf->il2m.vlan[0] = 0;
  }

  nl2 = &ntun->l2nh;
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;
 
  return 0;
}

static int __always_inline
dp_do_nh_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_nh_key key;
  struct dp_nh_tact *nha;
  int rnh = 0;
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  key.nh_num = (__u32)xf->pm.nh_num;

  BPF_TRACE_PRINTK("[NHFW] lkup %d", key.nh_num);
  xf->pm.table_id = LL_DP_NH_MAP;

  nha = bpf_map_lookup_elem(&nh_map, &key);
  if (!nha) {
    /* No NH - PASS */
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_UNK);
    return 0;
  }

  xf->pm.phit |= LLB_DP_NEIGH_HIT;
  BPF_TRACE_PRINTK("[NHFW] action %d pipe %x",
                nha->ca.act_type, xf->pm.pipe_act);

  if (nha->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (nha->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else if (nha->ca.act_type == DP_SET_NEIGH_L2) {
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_L2];
    ta->ca.act_type = nha->ca.act_type;
    memcpy(&ta->nl2,  &nha->rt_l2nh, sizeof(nha->rt_l2nh));
#endif
    rnh = dp_do_rt_l2_nh(ctx, xf, &nha->rt_l2nh);
    /* Check if need to do recursive next-hop lookup */
    if (rnh != 0) {
      key.nh_num = (__u32)rnh;
      nha = bpf_map_lookup_elem(&nh_map, &key);
      if (!nha) {
        /* No NH - PASS */
        LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_UNK);
        return 0;
      }
    }
  } 

  if (nha->ca.act_type == DP_SET_NEIGH_VXLAN) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_VXLAN];
    ta->ca.act_type = nha->ca.act_type;
    memcpy(&ta->ntun,  &nha->rt_tnh, sizeof(nha->rt_tnh));
#endif
    return dp_do_rt_tun_nh(ctx, xf, LLB_TUN_VXLAN, &nha->rt_tnh);
  } else if (nha->ca.act_type == DP_SET_NEIGH_IPIP) {
    return dp_do_rt_tun_nh(ctx, xf, LLB_TUN_IPIP, &nha->rt_tnh);
  }

  return 0;
}

static int __always_inline
dp_eg_l2(void *ctx,  struct xfi *xf, void *fa)
{
  /* Any processing based on results from L3 */
  if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {
    return 0;
  }   
      
  if (xf->pm.nh_num != 0) {
    dp_do_nh_lkup(ctx, xf, fa);
  }

  dp_do_map_stats(ctx, xf, LL_DP_TX_BD_STATS_MAP, xf->pm.bd);

  dp_do_dmac_lkup(ctx, xf, fa);
  return 0;
}

static int __always_inline
dp_ingress_fwd(void *ctx,  struct xfi *xf, void *fa)
{
  dp_ingress_l3(ctx, xf, fa);
  return dp_eg_l2(ctx, xf, fa);
}

static int __always_inline
dp_ingress_l2_top(void *ctx,  struct xfi *xf, void *fa)
{
  dp_do_smac_lkup(ctx, xf, fa);
  dp_do_tmac_lkup(ctx, xf, fa);
  dp_do_tun_lkup(ctx, xf, fa);

  if (xf->tm.tun_decap) {
    /* FIXME Also need to check if L2 tunnel */
    dp_do_smac_lkup(ctx, xf, fa);
    dp_do_tmac_lkup(ctx, xf, fa);
  }

  return 0;
}

static int __always_inline
dp_ingress_l2(void *ctx,  struct xfi *xf, void *fa)
{
  dp_ingress_l2_top(ctx, xf, fa);
  return dp_ingress_fwd(ctx, xf, fa);
}
