/*
 *  llb_kernel_devif.c: LoxiLB kernel eBPF dev in/out pipeline
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_IN_ACCOUNTING(ctx, xf)  \
do {                               \
  DP_SET_STARTS(xf);               \
}while(0)

#define DP_EG_ACCOUNTING(ctx, xf)  \
do {                               \
  TRACER_CALL(ctx, xf);            \
  RECPP_LATENCY(ctx, xf);          \
}while(0)

static int __always_inline
dp_do_if_lkup(void *ctx, struct xfi *xf)
{
  struct intf_key key;
  struct dp_intf_tact *l2a;

  key.ifindex = DP_IFI(ctx);
  key.ing_vid = xf->l2m.vlan[0];
  key.pad =  0;

  if (DP_LLB_IS_EGR(ctx)) {
    key.ifindex = DP_OIFI(ctx);
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  }

  BPF_TRACE_PRINTK("[INTF] lkup ifidx %d vid %d",
                key.ifindex, bpf_ntohs(key.ing_vid));
  
  xf->pm.table_id = LL_DP_SMAC_MAP;

  l2a = bpf_map_lookup_elem(&intf_map, &key);
  if (!l2a) {
    BPF_DBG_PRINTK("[INTF] intf not found");
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_UNX_DRP);
    return -1;
  }

  xf->pm.phit |= LLB_DP_IF_HIT;
  BPF_TRACE_PRINTK("[INTF] table action %d", l2a->ca.act_type);

  if (l2a->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_DROP);
  } else if (l2a->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_ACT_TRAP);
  } else if (l2a->ca.act_type == DP_SET_IFI) {
    xf->pm.iport = l2a->set_ifi.xdp_ifidx;
    xf->pm.zone  = l2a->set_ifi.zone;
    xf->pm.bd    = l2a->set_ifi.bd;
    xf->pm.mirr  = l2a->set_ifi.mirr;
    xf->pm.pten  = l2a->set_ifi.pten;
    xf->pm.pprop = l2a->set_ifi.pprop;
    xf->qm.ipolid = l2a->set_ifi.polid;
  } else {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  return 0;
}

#ifdef LL_TC_EBPF

static int __always_inline
dp_do_fixup_buf(void *ctx)
{
  struct __sk_buff *skb = DP_TC_PTR(ctx);

  if (skb->cb[2] != LLB_MARK_SKB_FIXUP && skb->len > LLB_SKB_FIXUP_LEN) {
    int *oif;
    int key;

    key = LLB_PORT_NO;
    oif = bpf_map_lookup_elem(&tx_intf_map, &key);
    if (!oif) {
      return DP_DROP;
    }

    dp_set_llb_mac_header(ctx);
    skb->cb[2] = LLB_MARK_SKB_FIXUP;
    //bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
    bpf_clone_redirect(skb, *oif, BPF_F_INGRESS);
    return DP_DROP;
  } else if (skb->cb[2] == LLB_MARK_SKB_FIXUP) {
    return DP_DROP;
  }
  return 0;
}

#ifdef HAVE_DP_BUF_FIXUP
#define DP_DO_BUF_FIXUP(ctx, xf)                            \
do {                                                        \
  if ((xf->pm.pipe_act & LLB_PIPE_DROP &&                   \
      xf->pm.rcode & LLB_PIPE_RC_PARSER) &&                 \
      ((struct __sk_buff *)ctx)->len > LLB_SKB_FIXUP_LEN) { \
    if (dp_do_fixup_buf(ctx)) {                             \
      return DP_DROP;                                       \
    }                                                       \
  }                                                         \
}while(0)
#else
#define DP_DO_BUF_FIXUP(ctx, xf)
#endif

static int __always_inline
dp_do_mark_mirr(void *ctx, struct xfi *xf)
{
  struct __sk_buff *skb = DP_TC_PTR(ctx);
  int *oif;
  int key;

  key = LLB_PORT_NO;
  oif = bpf_map_lookup_elem(&tx_intf_map, &key);
  if (!oif) {
    return -1;
  }

  skb->cb[0] = LLB_MIRR_MARK;
  skb->cb[1] = xf->pm.mirr; 

  BPF_TRACE_PRINTK("[REDR] mark mirror to port %d:%d", key, *oif);
  return bpf_clone_redirect(skb, *oif, BPF_F_INGRESS);
}

static int
dp_do_mirr_lkup(void *ctx, struct xfi *xf)
{
  struct dp_mirr_tact *ma;
  __u32 mkey = xf->pm.mirr;

  BPF_TRACE_PRINTK("[MIRR] lkup key %u", mkey);

  ma = bpf_map_lookup_elem(&mirr_map, &mkey);
  if (!ma) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_UNX_DRP);
    return -1;
  }

  BPF_TRACE_PRINTK("[MIRR] action %d", ma->ca.act_type);

  if (ma->ca.act_type == DP_SET_ADD_L2VLAN ||
      ma->ca.act_type == DP_SET_RM_L2VLAN) {
    struct dp_l2vlan_act *va = &ma->vlan_act;
    return dp_set_egr_vlan(ctx, xf,
                    ma->ca.act_type == DP_SET_RM_L2VLAN ?
                    0 : va->vlan, va->oport);
  }
  /* VXLAN to be done */

  LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  return -1;
}

#else

#define DP_DO_BUF_FIXUP(ctx, xf)

static int __always_inline
dp_do_mark_mirr(void *ctx, struct xfi *xf)
{
  return 0;
}

static int __always_inline
dp_do_mirr_lkup(void *ctx, struct xfi *xf)
{
  return 0;

}
#endif

static int __always_inline
dp_trap_packet(void *ctx,  struct xfi *xf, void *fa_)
{
  struct ethhdr *neth;
  struct ethhdr *oeth;
  uint16_t ntype;
  struct llb_ethhdr *llb;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  BPF_TRACE_PRINTK("[TRAP] start --");

  /* FIXME - There is a problem right now if we send decapped
   * packet up the stack. So, this is a safety check for now
   */
  //if (xf->tm.tun_decap)
  //  return DP_DROP;

  oeth = DP_TC_PTR(DP_PDATA(ctx));
  if (oeth + 1 > dend) {
    return DP_DROP;
  }

  /* If tunnel was present, outer metadata is popped */
  memcpy(xf->l2m.dl_dst, oeth->h_dest, 6*2);
  ntype = oeth->h_proto;

  if (dp_add_l2(ctx, (int)sizeof(*llb))) {
    /* This can fail to push headroom for tunnelled packets.
     * It might be better to pass it rather than drop it in case
     * of failure
     */
    return DP_PASS;
  }

  neth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (neth + 1 > dend) {
    return DP_DROP;
  }

  memcpy(neth->h_dest, xf->l2m.dl_dst, 6*2);
  neth->h_proto = bpf_htons(ETH_TYPE_LLB); 
  
  /* Add LLB shim */
  llb = DP_ADD_PTR(neth, sizeof(*neth));
  if (llb + 1 > dend) {
    return DP_DROP;
  }

  llb->iport = bpf_htons(xf->pm.iport);
  llb->oport = bpf_htons(xf->pm.oport);
  llb->rcode = xf->pm.rcode;
  if (xf->tm.tun_decap) {
    llb->rcode |= LLB_PIPE_RC_TUN_DECAP;
  }
  llb->mmap = xf->pm.table_id; /* FIXME */
  llb->ntype = ntype;

  xf->pm.oport = LLB_PORT_NO;
  if (dp_redirect_port(&tx_intf_map, xf) != DP_REDIRECT) {
    BPF_ERR_PRINTK("[TRAP] failed");
    return DP_DROP;
  }

  /* TODO - Apply stats */
  return DP_REDIRECT;
}

static int __always_inline
dp_redir_packet(void *ctx,  struct xfi *xf)
{
  if (dp_redirect_port(&tx_intf_map, xf) != DP_REDIRECT) {
    BPF_ERR_PRINTK("[REDI] failed");
    return DP_DROP;
  }

#ifdef LLB_DP_IF_STATS
  dp_do_map_stats(ctx, xf, LL_DP_TX_INTF_STATS_MAP, xf->pm.oport);
#endif

  return DP_REDIRECT;
}

static int __always_inline
dp_rewire_packet(void *ctx,  struct xfi *xf)
{
  if (dp_rewire_port(&tx_intf_map, xf) != DP_REDIRECT) {
    BPF_ERR_PRINTK("[REWR] failed");
    return DP_DROP;
  }

  return DP_REDIRECT;
}

#ifdef HAVE_DP_FUNCS
static int
#else
static int __always_inline
#endif
dp_pipe_check_res(void *ctx, struct xfi *xf, void *fa)
{
  BPF_TRACE_PRINTK("[PIPE] res act 0x%x", xf->pm.pipe_act);

  DP_EG_ACCOUNTING(ctx, xf);

  if (xf->pm.pipe_act) {

    if (xf->pm.pipe_act & LLB_PIPE_DROP) {
      return DP_DROP;
    }

    if (dp_unparse_packet_always(ctx, xf) != 0) {
        return DP_DROP;
    }

    if (xf->pm.ppv2) { 
      dp_ins_ppv2(ctx, xf);
    } else if (xf->pm.oppv2 | xf->pm.ippv2) {
      dp_fixup_ppv2(ctx, xf);
    }

    if (DP_LLB_IS_EGR(ctx)) {
      if (xf->pm.nf == 0 && xf->pm.nfc == 0) {
        return DP_PASS;
      }
      if (xf->pm.pipe_act & LLB_PIPE_TRAP) {
        xf->pm.pipe_act &= ~(LLB_PIPE_TRAP|LLB_PIPE_PASS);
        xf->pm.pipe_act |= LLB_PIPE_RDR;
        xf->pm.oport = xf->pm.iport;
        dp_swap_mac_header(ctx, xf);
        return dp_redirect_port_in(&tx_intf_map, xf);
      } else if (xf->pm.pipe_act & LLB_PIPE_PASS) {
        if (dp_unparse_packet(ctx, xf, 1) != 0) {
          return DP_DROP;
        }
        return DP_PASS;
      }
    }

#ifndef HAVE_LLB_DISAGGR
#ifdef HAVE_OOB_CH
    if (xf->pm.pipe_act & LLB_PIPE_TRAP) { 
      return dp_trap_packet(ctx, xf, fa);
    } 

    if (xf->pm.pipe_act & LLB_PIPE_PASS) {
#else
    if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {
#endif
      if (xf->pm.rcode & (LLB_PIPE_RC_NODMAC|LLB_PIPE_RC_NH_UNK)) {
        xf->pm.rcode |= LLB_PIPE_RC_RESOLVE;
        dp_ring_event(ctx, xf, 1);
      }
      return DP_PASS;
    }
#else
    if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) { 
      return dp_trap_packet(ctx, xf, fa);
    } 
#endif

    if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {
      if (dp_unparse_packet(ctx, xf, 0) != 0) {
        return DP_DROP;
      }
      return dp_redir_packet(ctx, xf);
    }

  } 
  return DP_PASS; /* FIXME */
}

static int __always_inline
dp_ing(void *ctx,  struct xfi *xf)
{
  dp_do_if_lkup(ctx, xf);
#ifdef LLB_DP_IF_STATS
  dp_do_map_stats(ctx, xf, LL_DP_INTF_STATS_MAP, xf->pm.iport);
#endif
  dp_do_map_stats(ctx, xf, LL_DP_BD_STATS_MAP, xf->pm.bd);

  if (xf->pm.mirr != 0) {
    dp_do_mark_mirr(ctx, xf);
  }

  if (xf->qm.ipolid != 0) {
    do_dp_policer(ctx, xf, 0);
  }

  return 0;
}

static int __always_inline
dp_insert_fcv4(void *ctx, struct xfi *xf, struct dp_fc_tacts *acts)
{
  struct dp_fcv4_key *key;
  int z = 0;
  int *oif;
  int pkey = xf->pm.oport;
  
  oif = bpf_map_lookup_elem(&tx_intf_map, &pkey);
  if (oif) {
    acts->ca.oaux = *oif;
  } 

  BPF_TRACE_PRINTK("[FCH] tbl insert");

  key = bpf_map_lookup_elem(&xfck, &z);
  if (key == NULL) {
    return -1;
  }

  if (bpf_map_lookup_elem(&fc_v4_map, key) != NULL) {
    return 1;
  }
  
  acts->pten = xf->pm.pten;
  bpf_map_update_elem(&fc_v4_map, key, acts, BPF_ANY);
  return 0;
}

/*
 * dp_ingress_slow_main - Detailed ingress processing (slow path)
 * ---------------------------------------------------------------
 * This function handles ingress packets that cannot be processed
 * through the fast-path cache (dp_ingress_fast_main).
 * It performs full packet inspection, policy evaluation, and
 * necessary state updates before determining the forwarding
 * or processing action.
 *
 * Key aspects:
 * - Handles cache misses and new updates new cache states.
 * - Performs deep packet inspection for L2-L4 fields.
 * - Updates connection tracking and policy enforcement state.
 * - Ensures packets are either forwarded, dropped, or passed
 *   to a fallback processing stage.
 *
 * While slower than the fast path, this function is essential
 * for learning and ensuring accurate forwarding decisions.
 */
static int __always_inline
dp_ingress_slow_main(struct __sk_buff *ctx,  struct xfi *xf)
{
  struct dp_fc_tacts *fa = NULL;
#ifdef HAVE_DP_FC
  int z = 0;

  fa = bpf_map_lookup_elem(&fcas, &z);
  if (!fa) return 0;

  /* No nonsense no loop */
  fa->ca.ftrap = 0;
  fa->ca.cidx = 0;
  fa->zone = 0;
  fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
  for (z = 0; z < LLB_FCV4_MAP_ACTS; z++) {
    fa->fcta[z].ca.act_type = 0;
  }

  /* memset is too costly */
  /*memset(fa->fcta, 0, sizeof(fa->fcta));*/
#endif

  BPF_TRACE_PRINTK("[INGR] start proc--");

  /* If there are any packets marked for mirroring, we do
   * it here and immediately get it out of way without
   * doing any further processing
   */
  if (xf->pm.mirr != 0) {
    dp_do_mirr_lkup(ctx, xf);
    goto out;
  }

  dp_ing(ctx, xf);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (xf->pm.pipe_act || xf->pm.tc == 0) {
    goto out;
  }

  dp_ingress_l2(ctx, xf, fa);

#ifdef HAVE_DP_FC
  /* fast-cache is used only when certain conditions are met */
  if (LLB_PIPE_FC_CAP(xf)) {
    fa->zone = xf->pm.zone;
    dp_insert_fcv4(ctx, xf, fa);
  }
#endif

out:
  xf->pm.phit |= LLB_DP_RES_HIT;

  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);
  return DP_PASS;
}

static int __always_inline
dp_ingress_ct_main(struct __sk_buff *ctx,  struct xfi *xf)
{
  int val = 0;
  struct dp_fc_tacts *fa = NULL;

#ifdef HAVE_DP_FC
  fa = bpf_map_lookup_elem(&fcas, &val);
  if (!fa) return DP_DROP;
#endif

  if (xf->pm.phit & LLB_DP_RES_HIT) {
    goto res_end;
  }

  if (xf->pm.phit & LLB_DP_NAT_HIT) {
    goto ct_start;
  }

  /* If ACL is hit, and packet arrives here 
   * it only means that we need CT processing.
   * In such a case, we skip nat lookup
   */
  if ((xf->pm.phit & LLB_DP_CTM_HIT) == 0) {

#ifdef HAVE_DP_FW
    if (xf->pm.fw_lid < LLB_FW4_MAP_ENTRIES) {
      bpf_tail_call(ctx, &pgm_tbl, LLB_DP_FW_PGM_ID);
      return DP_PASS;
    }
#endif

    if (xf->pm.dp_rec) {
      dp_record_it(ctx, xf);
    }

    if (!(xf->pm.dp_mark & LLB_MARK_NAT)) {
      dp_do_nat(ctx, xf);
    }

#ifdef HAVE_DP_LBMODE_ONLY
    if ((xf->pm.phit & LLB_DP_NAT_HIT) == 0) {
      return DP_PASS;
    }
#endif
  } else {
    if (xf->pm.fw_rid != 0) {
      dp_do_map_stats(ctx, xf, LL_DP_FW_STATS_MAP, xf->pm.fw_rid);
    }
  }

  /* CT pipeline is hit after acl lookup fails 
   * So, after CT processing we continue the rest
   * of the stack. We could potentially make 
   * another tail-call to where ACL lookup failed
   * and start over. But simplicity wins against
   * complexity for now 
   */
  dp_l3_fwd(ctx, xf, fa, 0);

  /* Perform masquerading if necessary */
  if ((xf->pm.phit & LLB_DP_CTM_HIT) == 0) {
    if (xf->pm.dp_mark & LLB_MARK_NAT) {
      bpf_tail_call(ctx, &pgm_tbl, LLB_DP_MASQ_PGM_ID);
      return DP_PASS;
    }
  }

ct_start:
  /* Perform conntrack */
  BPF_TRACE_PRINTK("[CTRK] ct-start");
  val = dp_ct_in(ctx, xf);
  if (val < 0) {
    return DP_PASS;
  }
  xf->nm.ct_sts = LLB_PIPE_CT_INP;

  dp_l3_fwd(ctx, xf, fa, 1);
  dp_eg_l2(ctx, xf, fa);

res_end:
  if (1) {
    int ret = dp_pipe_check_res(ctx, xf, fa);
    if (ret == DP_DROP) {
      BPF_TRACE_PRINTK("[RESO] dropped RC 0x%x", xf->pm.rcode);
    }
    return ret;
  }
}
 
static int __always_inline
dp_ingress_pass_main(void *ctx)
{
  BPF_TRACE_PRINTK("[INGR] pass--");

  return DP_PASS;
}
