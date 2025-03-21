/*
 *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_FWLKUP (400)
#define DP_MAX_LOOPS_PER_FW6LKUP (100)

#define RETURN_TO_MP() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID)

#define PDI_PKEY_EQ(v1, v2)                             \
  (((PDI_MATCH(&(v1)->dest, &(v2)->dest)))        &&    \
  ((PDI_MATCH(&(v1)->source, &(v2)->source)))     &&    \
  ((PDI_RMATCH(&(v1)->dport, &(v2)->dport)))      &&    \
  ((PDI_RMATCH(&(v1)->sport, &(v2)->sport)))      &&    \
  ((PDI_MATCH(&(v1)->inport, &(v2)->inport)))     &&    \
  ((PDI_MATCH(&(v1)->zone, &(v2)->zone)))         &&    \
  ((PDI_MATCH(&(v1)->protocol, &(v2)->protocol))) &&    \
  ((PDI_MATCH(&(v1)->bd, &(v2)->bd))))

#define PDI_PKEY6_EQ(v1, v2)                                \
  (((PDI_MATCH6(&(v1)->dest, &(v2)->dest)))           &&    \
  ((PDI_MATCH6(&(v1)->source, &(v2)->source)))        &&    \
  ((PDI_RMATCH(&(v1)->dport, &(v2)->dport)))          &&    \
  ((PDI_RMATCH(&(v1)->sport, &(v2)->sport)))          &&    \
  ((PDI_MATCH(&(v1)->inport, &(v2)->inport)))         &&    \
  ((PDI_MATCH(&(v1)->zone, &(v2)->zone)))             &&    \
  ((PDI_MATCH(&(v1)->protocol, &(v2)->protocol)))     &&    \
  ((PDI_MATCH(&(v1)->bd, &(v2)->bd))))

static int __always_inline
dp_do_fw4_main(void *ctx, struct xfi *xf)
{
  __u32 idx = 0;
  int i = 0;
  struct dp_fwv4_ent *fwe;
  struct pdi_key key;
  struct dp_fw_tact *act = NULL;

  memset(&key, 0, sizeof(key));
  PDI_VAL_INIT(&key.inport, xf->pm.iport);
  PDI_VAL_INIT(&key.zone, xf->pm.zone);
  PDI_VAL_INIT(&key.bd, xf->pm.bd);
  PDI_VAL_INIT(&key.dest, bpf_ntohl(xf->l34m.daddr4));
  PDI_VAL_INIT(&key.source, bpf_ntohl(xf->l34m.saddr4));
  PDI_RVAL_INIT(&key.dport, bpf_htons(xf->l34m.dest));
  PDI_RVAL_INIT(&key.sport, bpf_htons(xf->l34m.source));
  PDI_VAL_INIT(&key.protocol, xf->l34m.nw_proto);

  xf->pm.table_id = LL_DP_FW4_MAP;

  idx = xf->pm.fw_lid;

  for (i = 0; i < DP_MAX_LOOPS_PER_FWLKUP; i++) {

    fwe = bpf_map_lookup_elem(&fw_v4_map, &idx);
    if (!fwe) {
      BPF_DBG_PRINTK("[FW4] lkup miss");
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
      RETURN_TO_MP();
      return DP_DROP;
    } else {
      if (idx == 0) {
        xf->pm.fw_mid = fwe->k.nr.val;
      } else if (i + xf->pm.fw_lid >= xf->pm.fw_mid) {
        i = DP_MAX_LOOPS_PER_FWLKUP;
        break;
      }

      idx++;

      if (fwe->k.zone.val != 0 && 
          PDI_PKEY_EQ(&key, &fwe->k)) {

        /* End of lookup */
        xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
        break;
      }
    }
  }

  if (i >= DP_MAX_LOOPS_PER_FWLKUP) {
    /* No match in this iteration */
    xf->pm.fw_lid += DP_MAX_LOOPS_PER_FWLKUP;
    if (xf->pm.fw_lid >= LLB_FW4_MAP_ENTRIES ||
        xf->pm.fw_lid > xf->pm.fw_mid) {
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
    }
    BPF_TRACE_PRINTK("[FW4] lkup done");
    RETURN_TO_MP();
    return DP_DROP;
  }

  xf->pm.phit |= LLB_DP_FW_HIT;

  /* This condition should never hit */
  if (!fwe) return 0;

  act = &fwe->fwa;

  xf->pm.dp_mark = act->ca.mark;
  xf->pm.dp_rec = act->ca.record;

  if (act->ca.act_type == DP_SET_NOP) {
    goto done;
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;
    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_FW_RDR);
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  xf->pm.phit |= LLB_DP_RES_HIT;

done:
  dp_do_map_stats(ctx, xf, LL_DP_FW_STATS_MAP, act->ca.cidx);
  xf->pm.fw_rid = act->ca.cidx;

  RETURN_TO_MP();
  xf->pm.rcode |= LLB_PIPE_RC_TCALL_ERR;
  return DP_DROP;
}

static int __always_inline
dp_do_fw6_main(void *ctx, struct xfi *xf)
{
  __u32 idx = 0;
  int i = 0;
  struct dp_fwv6_ent *fwe;
  struct pdi6_key key;
  struct dp_fw_tact *act = NULL;

  memset(&key, 0, sizeof(key));
  PDI_VAL_INIT(&key.inport, xf->pm.iport);
  PDI_VAL_INIT(&key.zone, xf->pm.zone);
  PDI_VAL_INIT(&key.bd, xf->pm.bd);
  PDI_VAL6_INIT(&key.dest, xf->l34m.daddr);
  PDI_VAL6_INIT(&key.source, xf->l34m.saddr);
  PDI_RVAL_INIT(&key.dport, bpf_htons(xf->l34m.dest));
  PDI_RVAL_INIT(&key.sport, bpf_htons(xf->l34m.source));
  PDI_VAL_INIT(&key.protocol, xf->l34m.nw_proto);

  xf->pm.table_id = LL_DP_FW6_MAP;

  idx = xf->pm.fw_lid;

  for (i = 0; i < DP_MAX_LOOPS_PER_FW6LKUP; i++) {

    fwe = bpf_map_lookup_elem(&fw_v6_map, &idx);
    if (!fwe) {
      BPF_DBG_PRINTK("[FW6] lkup miss");
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
      RETURN_TO_MP();
      return DP_DROP;
    } else {
      if (idx == 0) {
        xf->pm.fw_mid = fwe->k.nr.val;
      } else if (i + xf->pm.fw_lid >= xf->pm.fw_mid) {
        i = DP_MAX_LOOPS_PER_FW6LKUP;
        break;
      }

      idx++;

      if (fwe->k.zone.val != 0 && 
          PDI_PKEY6_EQ(&key, &fwe->k)) {

        /* End of lookup - Note that we are setting LLB_FW4_MAP_ENTRIES 
         * instead of LLB_FW6_MAP_ENTRIES because LLB_FW4_MAP_ENTRIES is
         * used as a marker for end of tailcall to fw
         */
        xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
        break;
      }
    }
  }

  if (i >= DP_MAX_LOOPS_PER_FW6LKUP) {
    /* No match in this iteration */
    xf->pm.fw_lid += DP_MAX_LOOPS_PER_FW6LKUP;
    if (xf->pm.fw_lid >= LLB_FW6_MAP_ENTRIES ||
        xf->pm.fw_lid > xf->pm.fw_mid) {
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
    }
    BPF_TRACE_PRINTK("[FW6] lkup done");
    RETURN_TO_MP();
    return DP_DROP;
  }

  xf->pm.phit |= LLB_DP_FW_HIT;

  /* This condition should never hit */
  if (!fwe) return 0;

  act = &fwe->fwa;

  xf->pm.dp_mark = act->ca.mark;
  xf->pm.dp_rec = act->ca.record;

  if (act->ca.act_type == DP_SET_NOP) {
    goto done;
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;
    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_FW_RDR);
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_ACT_UNK);
  }

  xf->pm.phit |= LLB_DP_RES_HIT;

done:
  dp_do_map_stats(ctx, xf, LL_DP_FW_STATS_MAP, act->ca.cidx);
  xf->pm.fw_rid = act->ca.cidx;

  RETURN_TO_MP();
  xf->pm.rcode |= LLB_PIPE_RC_TCALL_ERR;
  return DP_DROP;
}

static int __always_inline
dp_do_fw_main(void *ctx, struct xfi *xf)
{
  if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
    return dp_do_fw6_main(ctx, xf);
  } else {
    return dp_do_fw4_main(ctx, xf);
  }
}
