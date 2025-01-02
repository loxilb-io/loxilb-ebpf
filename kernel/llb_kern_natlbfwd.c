/*
 *  llb_kern_nat.c: LoxiLB Kernel eBPF Stateful NAT/LB Processing
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define LLB_MAX_NXFRMS_PLOOP (10)
#define EP_DPTO              (30000000000)
#define TCALL_NAT_TC1() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_SNAT_PGM_ID1)

static void __always_inline
dp_do_rst_nat_sess(void *ctx, struct xfi *xf, __u32 rule, __u16 aid)
{
  struct dp_nat_epacts *epa;
  epa = bpf_map_lookup_elem(&nat_ep_map, &rule);
  if (epa != NULL) {
    bpf_spin_lock(&epa->lock);
    if (aid < LLB_MAX_NXFRMS) {
      if (epa->ca.act_type == DP_SET_NACT_SESS) {
        epa->active_sess[aid].csess--;
      }
    }
    bpf_spin_unlock(&epa->lock);
  }
}

static void __always_inline
dp_do_rst_ep_sess(void *ctx, struct xfi *xf, __u32 rule, __u16 aid)
{
  struct dp_nat_sepacts *epa;
  __u64 flags = BPF_F_CURRENT_CPU;
  __u32 key = (rule * LLB_MAX_NXFRMS) +  aid;

  if (xf->pm.nf == 0) {
    return;
  }

  epa = bpf_map_lookup_elem(&nat_sep_map, &key);
  if (epa != NULL) {
    bpf_spin_lock(&epa->lock);
    struct epsess *eps = &epa->active_sess;
    // Reset only if ep-slot is fully used
    if (eps->udp) {
      eps->lts = 0;
      eps->tcp = 0;
      eps->udp = 0;
      eps->id = 0;
      bpf_spin_unlock(&epa->lock);
      flags |= (__u64)(sizeof(struct epsess)) << 32;
      bpf_perf_event_output(ctx, &sync_ring, flags,
                        eps, sizeof(struct epsess));
      return;
    }
    bpf_spin_unlock(&epa->lock);
  }
}

static void __always_inline
dp_update_ep_sess(void *ctx, struct xfi *xf, __u32 rule, __u16 aid)
{
  struct dp_nat_sepacts *epa;
  __u64 flags = BPF_F_CURRENT_CPU;
  __u64 cts = bpf_ktime_get_ns();
  __u32 key = (rule * LLB_MAX_NXFRMS) +  aid;

  if (xf->pm.nf == 0) {
    return;
  }

  epa = bpf_map_lookup_elem(&nat_sep_map, &key);
  if (epa != NULL) {
    // FIXME : Do we need to care about race-condition here ?
    bpf_spin_lock(&epa->lock);
    struct epsess *eps = &epa->active_sess;
    if (cts - eps->lts > 10000000000 && eps->rid && eps->udp) {
      eps->lts = cts;
      bpf_spin_unlock(&epa->lock);
      flags |= (__u64)(sizeof(struct epsess)) << 32;
      bpf_perf_event_output(ctx, &sync_ring, flags,
                        eps, sizeof(struct epsess));
      return;
    }
    bpf_spin_unlock(&epa->lock);
  }
}

static int __always_inline
dp_sel_nat_ep_persist_check_slot(void *ctx, struct xfi *xf,
                                 struct dp_proxy_tacts *act, 
                                 uint16_t sel, int is_udp)
{
  struct dp_nat_sepacts *epa;
  struct epsess *eps;
  uint16_t n;
  __u32 key;
  __u32 key_base;
  __u32 id;
  __u64 flags = BPF_F_CURRENT_CPU;
  __u64 cts = bpf_ktime_get_ns();

  flags |= (__u64)(sizeof(struct epsess)) << 32;
  id = xf->l34m.saddr4;
  key_base = act->ca.cidx * LLB_MAX_NXFRMS;
  for (n = 0; n < LLB_MAX_NXFRMS_PLOOP; n++) {
    if (sel < LLB_MAX_NXFRMS) {
      if (act->nxfrms[sel].inactive == 0) {
        key = key_base + sel;
        epa = bpf_map_lookup_elem(&nat_sep_map, &key);
        if (epa != NULL) {
          bpf_spin_lock(&epa->lock);
          eps = &epa->active_sess;
          if ((cts - eps->lts > EP_DPTO) ||
              ((eps->id == id) &&
              ((eps->tcp == 0 && !is_udp) ||
              ((eps->udp == 0 && is_udp))))) {
            eps->lts = cts;
            eps->id = id;
            if (is_udp) {
              eps->udp = 1;
            } else {
              eps->tcp = 1;
              eps->udp = 0;
            }
            bpf_spin_unlock(&epa->lock);
            bpf_perf_event_output(ctx, &sync_ring, flags,
                          eps, sizeof(*eps));
            return sel;
          }
          bpf_spin_unlock(&epa->lock);
        }
      }
      sel++;
      sel = sel % LLB_MAX_NXFRMS;
    }
  }

  *(__u16 *)&xf->km.skey[4] = sel;
  return (uint16_t)(-1);
}

static int __always_inline
dp_sel_nat_ep_persist(void *ctx, struct xfi *xf, struct dp_proxy_tacts *act, int is_udp)
{
  uint16_t sel = -1;
  __u64 now = bpf_ktime_get_ns();
  __u64 base;
  __u64 tfc = 0;

  bpf_spin_lock(&act->lock);
  if (act->base_to == 0 || now - act->lts > act->pto)
  {
    act->base_to = now;
  }
  base = act->base_to;
  if (act->pto) {
    tfc = base / act->pto;
  } else {
    act->pto = NAT_LB_PERSIST_TIMEOUT;
    tfc = base / NAT_LB_PERSIST_TIMEOUT;
  }
  sel = *(__u16 *)&xf->km.skey[4];
  if (sel == 0) {
#ifdef HAVE_DP_PERSIST_TFC
    sel = get_ip4_hash(xf->l34m.saddr4) ^ (tfc & 0xff);
#else
    sel = get_ip4_hash(xf->l34m.saddr4);
#endif
    sel %= act->nxfrm;
  }
  act->lts = now;
  bpf_spin_unlock(&act->lock);
  if (sel < LLB_MAX_NXFRMS) {
    sel = dp_sel_nat_ep_persist_check_slot(ctx, xf, act, sel, is_udp);
    //bpf_printk("port %d sel2 %d tcp %d", bpf_ntohs(xf->l34m.source), sel, !is_udp);
  }
  return sel;
}

static int __always_inline
dp_sel_nat_ep(void *ctx, struct xfi *xf, struct dp_proxy_tacts *act, int is_udp)
{
  uint16_t sel = -1;
  uint16_t n = 0;
  uint16_t i = 0;
  struct mf_xfrm_inf *nxfrm_act;

  if (act->sel_type == NAT_LB_SEL_RR) {
    bpf_spin_lock(&act->lock);
    i = act->sel_hint; 

    while (n < LLB_MIN_NXFRMS) {
      if (i >= 0 && i < LLB_MAX_NXFRMS) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act->inactive == 0) {
          act->sel_hint = (i + 1) % LLB_MIN_NXFRMS;
          sel = i;
          break;
        }
      }
      i++;
      if (i >= LLB_MIN_NXFRMS)  i = 0;
      n++;
    }
    bpf_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_HASH) {
    sel = dp_get_pkt_hash(ctx) % act->nxfrm;
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      /* Fall back if hash selection gives us a deadend */
      if (act->nxfrms[sel].inactive) {
        for (i = 0; i < LLB_MIN_NXFRMS; i++) {
          if (act->nxfrms[i].inactive == 0) {
            sel = i;
            break;
          }
        }
      }
    }
  } else if (act->sel_type == NAT_LB_SEL_N3) {
    if (xf->tm.tun_type == LLB_TUN_GTP) {
      sel = dp_get_tun_hash(xf) % act->nxfrm;
      if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
        /* Fall back if hash selection gives us a deadend */
        if (act->nxfrms[sel].inactive) {
          for (i = 0; i < LLB_MIN_NXFRMS; i++) {
            if (act->nxfrms[i].inactive == 0) {
              sel = i;
              break;
            }
          }
        }
      }
    }
  } else if (act->sel_type == NAT_LB_SEL_RR_PERSIST) {
    uint16_t nep = *(__u16 *)&xf->km.skey[2];
    sel = dp_sel_nat_ep_persist(ctx, xf, act, is_udp);
    if (sel == (uint16_t)(-1)) {
      nep += LLB_MAX_NXFRMS_PLOOP;
      if (nep < LLB_MAX_NXFRMS) {
        *(__u16 *)&xf->km.skey[2] = nep;
        TCALL_NAT_TC1();
      }
      // Give up but with a fight
      //sel = get_ip4_hash3(xf->l34m.saddr4) % act->nxfrm;
    }
  } else if (act->sel_type == NAT_LB_SEL_LC) {
    struct dp_nat_epacts *epa;
    __u32 key = act->ca.cidx; //rule num
    __u32 lc = 0;
    epa = bpf_map_lookup_elem(&nat_ep_map, &key);
    if (epa != NULL) {
      epa->ca.act_type = DP_SET_NACT_SESS;
      bpf_spin_lock(&epa->lock);
      for (i = 0; i < LLB_MIN_NXFRMS; i++) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act->inactive == 0) {
          __u32 as = epa->active_sess[i].csess;
          if (lc > as || sel == (uint16_t)(-1)) {
            sel = i;
            lc = as;
          }
        }
      }
      if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
        epa->active_sess[sel].csess++;
      }
      bpf_spin_unlock(&epa->lock);
    }
  }

  LL_DBG_PRINTK("lb-sel %d", sel);

  return sel;
}

static int __always_inline
dp_do_nat(void *ctx, struct xfi *xf)
{
  struct dp_nat_key key;
  struct mf_xfrm_inf *nxfrm_act;
  struct dp_proxy_tacts *act;
  int sel;

  if (xf->pm.l4fin || xf->pm.il4fin) {
    return 0;
  }

  int is_udp = xf->l34m.nw_proto == IPPROTO_UDP ? 1:0;

  memset(&key, 0, sizeof(key));
  key.mark = xf->pm.dp_mark;

  if (!(key.mark & 0x80000000)) {
    DP_XADDR_CP(key.daddr, xf->l34m.daddr);
    if (xf->l34m.nw_proto != IPPROTO_ICMP) {
      key.dport = xf->l34m.dest;
    } else {
      key.dport = 0;
    }
    key.zone = xf->pm.zone;
    key.l4proto = xf->l34m.nw_proto;
    // FIXME - Use same rule for UDP as TCP
    if (key.l4proto == IPPROTO_UDP) {
      key.l4proto = IPPROTO_TCP;
    }
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
      key.v6 = 1;
    }

    if (key.mark & 0x40000000) {
      key.mark = 0;
    }
  }

  LL_DBG_PRINTK("[NAT] Lookup");

  xf->pm.table_id = LL_DP_NAT_MAP;

  act = bpf_map_lookup_elem(&nat_map, &key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~LLB_NAT_SRC;
    return 0;
  }

  xf->pm.phit |= LLB_DP_NAT_HIT;
  LL_DBG_PRINTK("[NAT] action %d pipe %x\n",
                 act->ca.act_type, xf->pm.pipe_act);

  if (act->opflags & NAT_LB_OP_CHKSRC) {
    __u32 bm = (1 << act->ca.cidx) & 0xffffff;
    if (!(xf->pm.dp_mark & bm)) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
      return 1;
    }
  }

  if (act->ca.act_type == DP_SET_SNAT || 
      act->ca.act_type == DP_SET_DNAT) {
    sel = dp_sel_nat_ep(ctx, xf, act, is_udp);

    xf->nm.dsr = act->ca.oaux ? 1: 0;
    xf->nm.cdis = act->cdis ? 1: 0;
    xf->nm.ppv2 = act->ppv2 ? 1: 0;
    xf->pm.nf = act->ca.act_type == DP_SET_SNAT ? LLB_NAT_SRC : LLB_NAT_DST;
    xf->nm.npmhh = act->npmhh;
    xf->nm.pmhh[0] = act->pmhh[0];
    xf->nm.pmhh[1] = act->pmhh[1];
    xf->nm.pmhh[2] = act->pmhh[2];  // LLB_MAX_MHOSTS

    /* FIXME - Do not select inactive end-points 
     * Need multi-passes for selection
     */
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      nxfrm_act = &act->nxfrms[sel];

      DP_XADDR_CP(xf->nm.nxip, nxfrm_act->nat_xip);
      DP_XADDR_CP(xf->nm.nrip, nxfrm_act->nat_rip);
      xf->nm.nxport = nxfrm_act->nat_xport;
      xf->nm.nv6 = nxfrm_act->nv6 ? 1: 0;
      xf->nm.sel_aid = sel;
      xf->nm.ito = act->ito;
      xf->pm.rule_id =  act->ca.cidx;
      LL_DBG_PRINTK("[NAT] ACT %x", xf->pm.nf);
      /* Special case related to host-dnat */
      if (!xf->nm.nv6 && xf->l34m.saddr4 == xf->nm.nxip4 && xf->pm.nf == LLB_NAT_DST) {
        xf->nm.nxip4 = 0;
      }
    } else {
      xf->pm.nf = 0;
    }

  } else { 
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  return 1;
}
