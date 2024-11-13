/*
 *  llb_kern_l3fwd.c: LoxiLB Kernel eBPF L3 forwarder Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
static int __always_inline
dp_do_rt4_fwdops(void *ctx, struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(DP_PDATA(ctx) + xf->pm.l3_off);
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (iph + 1 > dend)  {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLRT_ERR);
    return -1;
  }
  ip_decrease_ttl(iph);
  return 0;
}

static int __always_inline
dp_do_rt6_fwdops(void *ctx, struct xfi *xf)
{
  struct ipv6hdr *ip6h = DP_TC_PTR(DP_PDATA(ctx) + xf->pm.l3_off);
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (ip6h + 1 > dend)  {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLRT_ERR);
    return -1;
  }
  ip6h->hop_limit--;
  return 0;
}

static int __always_inline
dp_do_rt_fwdops(void *ctx, struct xfi *xf)
{
  if (xf->l2m.dl_type == ETH_P_IP) {
    return dp_do_rt4_fwdops(ctx, xf);
  } else if (xf->l2m.dl_type == ETH_P_IPV6) {
    return dp_do_rt6_fwdops(ctx, xf);
  }
  return DP_DROP;
}

static int __always_inline
dp_pipe_set_l32_tun_nh(void *ctx, struct xfi *xf,
                       struct dp_rt_nh_act *rnh)
{
  struct dp_rt_l2nh_act *nl2;
  xf->pm.nh_num = rnh->nh_num[0];
  /*
   * We do not set out_bd here. After NH lookup match is
   * found and packet tunnel insertion is done, BD is set accordingly
   */
  /*xf->pm.bd = rnh->bd;*/
  xf->tm.new_tunnel_id = rnh->tid;

  nl2 = &rnh->l2nh;
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;

  LL_DBG_PRINTK("[RTFW] new-vx nh %u\n", xf->pm.nh_num);
  return 0;
}

static __u32 __always_inline
dp_rtv4_get_ipkey(struct xfi *xf)
{
  __u32 ipkey;

  if (xf->pm.nf & LLB_NAT_DST) {
    ipkey = xf->nm.nxip4?:xf->l34m.saddr4;
  } else {
    if (xf->pm.nf & LLB_NAT_SRC) {
      if (xf->nm.nrip4) {
        ipkey = xf->nm.nrip4;
      } else if (xf->nm.nxip4 == 0) {
        ipkey = xf->l34m.saddr4;
      } else {
        ipkey = xf->l34m.daddr4;
      }
    } else {
      if (xf->tm.new_tunnel_id && xf->tm.tun_type == LLB_TUN_GTP) {
        /* In case of GTP, there is no interface created in OS 
         * which has a specific route through it. So, this hack !!
         */
        ipkey = xf->tm.tun_rip;
      } else {
        ipkey = xf->l34m.daddr4;
      }
    }
  }
  return ipkey;
}

static int __always_inline
dp_do_rtops(void *ctx, struct xfi *xf, void *fa_, struct dp_rt_tact *act)
{
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  LL_DBG_PRINTK("[RTFW] action %d pipe %x\n",
                act->ca.act_type, xf->pm.pipe_act);

  if (act->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (act->ca.act_type == DP_SET_TOCP) {
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_TOCP];
    ta->ca.act_type = act->ca.act_type;
#endif
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_RT_TRAP);
  } else if (act->ca.act_type == DP_SET_NOP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_RT_TRAP);
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ra = &act->port_act;
    LLBS_PPLN_RDR(xf);
    xf->pm.oport = ra->oport;
  } else if (act->ca.act_type == DP_SET_RT_NHNUM) {
    struct dp_rt_nh_act *rnh = &act->rt_nh;

    if (rnh->naps > 1) {
      int sel = dp_get_pkt_hash(ctx) % rnh->naps;
      if (sel >= 0 && sel < DP_MAX_ACTIVE_PATHS) {
        xf->pm.nh_num = rnh->nh_num[sel];
      }
    } else {
      xf->pm.nh_num = rnh->nh_num[0];
    }
    return dp_do_rt_fwdops(ctx, xf);
  } /*else if (act->ca.act_type == DP_SET_L3RT_TUN_NH) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_L3RT_TUN_NH];
    ta->ca.act_type = DP_SET_L3RT_TUN_NH;
    memcpy(&ta->nh_act,  &act->rt_nh, sizeof(act->rt_nh));
#endif
    return dp_pipe_set_l32_tun_nh(ctx, xf, &act->rt_nh);
  } */ else {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  return 0;
}

static int __always_inline
dp_do_rtv6(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_rtv6_key *key = (void *)xf->km.skey;
  struct dp_rt_tact *act;

  key->l.prefixlen = 128; /* 128-bit prefix */

  if (xf->pm.nf & LLB_NAT_DST) {
    if (DP_XADDR_ISZR(xf->nm.nxip)) {
      DP_XADDR_CP(key->addr, xf->l34m.saddr);
    } else {
      DP_XADDR_CP(key->addr, xf->nm.nxip);
    }
  } else {
    if (xf->pm.nf & LLB_NAT_SRC) {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        DP_XADDR_CP(key->addr, xf->nm.nrip);
      } else if (DP_XADDR_ISZR(xf->nm.nxip)) {
        DP_XADDR_CP(key->addr, xf->l34m.saddr);
      } else {
        DP_XADDR_CP(key->addr, xf->l34m.daddr);
      }
    } else {
        DP_XADDR_CP(key->addr, xf->l34m.daddr);
    }
  }

  LL_DBG_PRINTK("[RT6FW] --Lookup");
  LL_DBG_PRINTK("[RT6FW] --addr0 %x", key->addr[0]);
  LL_DBG_PRINTK("[RT6FW] --addr1 %x", key->addr[1]);
  LL_DBG_PRINTK("[RT6FW] --addr2 %x", key->addr[2]);
  LL_DBG_PRINTK("[RT6FW] --addr3 %x", key->addr[3]);

  xf->pm.table_id = LL_DP_RTV6_MAP;

  act = bpf_map_lookup_elem(&rt_v6_map, key);
  if (!act) {
    xf->pm.nf &= ~LLB_NAT_SRC;
    if (!DP_LLB_IS_EGR(ctx)) {
      LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_RT_TRAP);
    } else {
      LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_RT_TRAP);
    }
    return 0;
  }

  xf->pm.phit |= LLB_DP_RT_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_RTV6_STATS_MAP, act->ca.cidx);

  return dp_do_rtops(ctx, xf, fa_, act);
}

static int __always_inline
dp_do_rtv4(void *ctx, struct xfi *xf, void *fa_)
{
  //struct dp_rtv4_key key = { 0 };
  struct dp_rtv4_key *key = (void *)xf->km.skey;
  struct dp_rt_tact *act;

  key->l.prefixlen = 48; /* 16-bit zone + 32-bit prefix */
  key->v4k[0] = xf->pm.zone >> 8 & 0xff;
  key->v4k[1] = xf->pm.zone & 0xff;

  *(__u32 *)&key->v4k[2] = dp_rtv4_get_ipkey(xf);
  
  LL_DBG_PRINTK("[RTFW] Lookup");
  LL_DBG_PRINTK("[RTFW] Zone %d 0x%x",
                 xf->pm.zone, *(__u32 *)&key->v4k[2]);

  xf->pm.table_id = LL_DP_RTV4_MAP;

  act = bpf_map_lookup_elem(&rt_v4_map, key);
  if (!act) {
    xf->pm.nf &= ~LLB_NAT_SRC;
    if (!DP_LLB_IS_EGR(ctx)) {
      LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_RT_TRAP);
    } else {
      LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_RT_TRAP);
    }
    return 0;
  }

  xf->pm.phit |= LLB_DP_RT_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_RTV4_STATS_MAP, act->ca.cidx);

  return dp_do_rtops(ctx, xf, fa_, act);
}

static int __always_inline
dp_pipe_set_nat(void *ctx, struct xfi *xf, 
                struct dp_nat_act *na, int do_snat)
{
  xf->pm.nf = do_snat ? LLB_NAT_SRC : LLB_NAT_DST;
  DP_XADDR_CP(xf->nm.nxip, na->xip);
  DP_XADDR_CP(xf->nm.nrip, na->rip);
  xf->nm.nxport = na->xport;
  xf->nm.nv6 = na->nv6 ? 1 : 0;
  xf->nm.dsr = na->dsr;
  xf->nm.cdis = na->cdis;
  xf->nm.npmhh = na->nmh;
  LL_DBG_PRINTK("[CT] NAT ACT %x", xf->pm.nf);

  return 0;
}

static int __always_inline
dp_do_ctops(void *ctx, struct xfi *xf, void *fa_, 
             struct dp_ct_tact *act)
{
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  if (!act) {
    LL_DBG_PRINTK("[CT] miss");
    goto ct_trk;
  }

  xf->pm.phit |= LLB_DP_CTM_HIT;
  act->lts = bpf_ktime_get_ns();

#ifdef HAVE_DP_FC
  fa->ca.cidx = act->ca.cidx;
  fa->ca.fwrid = act->ca.fwrid;
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
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, LLB_NAT_STAT_CID(na->rid, na->aid));

    if (na->fr == 1 || na->doct || xf->pm.goct) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACL_TRAP);
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  }

#ifdef HAVE_DP_EXTCT
  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    dp_run_ctact_helper(xf, act);
  }
#endif

  if (act->ca.fwrid != 0) {
    if (act->ca.record) {
      dp_record_it(ctx, xf);
      xf->pm.dp_rec = act->ca.record;
    }
    dp_do_map_stats(ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.fwrid);
  }
  dp_do_map_stats(ctx, xf, LL_DP_CT_STATS_MAP, act->ca.cidx);
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

static int __always_inline
dp_do_ing_ct(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  LL_DBG_PRINTK("[CT] Lookup");
  LL_DBG_PRINTK("[CT] daddr %x", key.daddr[0]);
  LL_DBG_PRINTK("[CT] saddr %x", key.saddr[0]);
  LL_DBG_PRINTK("[CT] sport %d", key.sport);
  LL_DBG_PRINTK("[CT] dport %d", key.dport);
  LL_DBG_PRINTK("[CT] l4proto %d", key.l4proto);
  LL_DBG_PRINTK("[CT] ident %lu", key.ident);
  LL_DBG_PRINTK("[CT] type %lu", key.type);

  xf->pm.table_id = LL_DP_CT_MAP;
  act = bpf_map_lookup_elem(&ct_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[CT] miss");
  }

  return dp_do_ctops(ctx, xf, fa_, act);
}

static void __always_inline
dp_do_ipv4_fwd(void *ctx,  struct xfi *xf, void *fa_)
{
  /* Check tunnel initiation */
  if (xf->tm.tunnel_id == 0 ||  xf->tm.tun_type != LLB_TUN_GTP) {
    dp_do_sess4_lkup(ctx, xf);
  }
#ifndef HAVE_DP_LBMODE_ONLY
  if (xf->pm.phit & LLB_DP_TMAC_HIT) {
#else
  if (1) {
#endif

    /* If some pipeline block already set a redirect before this,
     * we honor this and dont do further l3 processing 
     */
    if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {
      dp_do_rtv4(ctx, xf, fa_);
    }
  }
}

static void __always_inline
dp_do_ipv6_fwd(void *ctx,  struct xfi *xf, void *fa_)
{

#ifndef HAVE_DP_LBMODE_ONLY
  if (xf->pm.phit & LLB_DP_TMAC_HIT) {
#else
  if (1) {
#endif

    /* If some pipeline block already set a redirect before this,
     * we honor this and dont do further l3 processing
     */
    if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {
      dp_do_rtv6(ctx, xf, fa_);
    }
  }
}

static int __always_inline
dp_l3_fwd(void *ctx,  struct xfi *xf, void *fa)
{
  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    if (xf->pm.nf && xf->nm.nv6 != 0) {
      xf->nm.xlate_proto = 1;
      dp_do_ipv6_fwd(ctx, xf, fa);
    } else {
      dp_do_ipv4_fwd(ctx, xf, fa);
    }
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (xf->pm.nf && xf->nm.nv6 == 0) {
      xf->nm.xlate_proto = 1;
      dp_do_ipv4_fwd(ctx, xf, fa);
    } else {
      dp_do_ipv6_fwd(ctx, xf, fa);
    }
  }
  return 0;
}

static int __always_inline
dp_ing_l3(void *ctx,  struct xfi *xf, void *fa)
{
  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    /* Check termination */
    if (xf->tm.tunnel_id &&
        (xf->tm.tun_type == LLB_TUN_GTP || xf->tm.tun_type == LLB_TUN_IPIP)) {
      dp_do_sess4_lkup(ctx, xf);
    }
  }

  dp_do_ing_ct(ctx, xf, fa);
  dp_l3_fwd(ctx, xf, fa);

  return 0;
}
