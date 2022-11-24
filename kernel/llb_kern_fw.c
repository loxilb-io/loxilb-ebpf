/*
 *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_FWLKUP (1000)

#define RETURN_TO_MP() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID)

static int __always_inline
dp_do_fw4_main(void *ctx, struct xfi *xf)
{
  __u32 idx = 0;
  int i = 0;
  struct dp_fwv4_ent *fwe;
  struct dp_fwv4_key key;
  struct dp_fwv4_tact *act = NULL;

  key.inport = xf->pm.iport;
  key.zone = xf->pm.zone;
  key.bd = xf->pm.bd;
  key.oport = xf->pm.oport;
  key.daddr = xf->l3m.ip.daddr;
  key.saddr = xf->l3m.ip.saddr;
  key.sport = xf->l3m.source;
  key.dport = xf->l3m.dest;
  key.l4proto = xf->l3m.nw_proto;
  key.nr = 0;
  key.res = 0;

  LL_DBG_PRINTK("[FW4] -- Lookup\n");
  LL_DBG_PRINTK("[FW4] key-sz %d\n", sizeof(key));
  LL_DBG_PRINTK("[FW4] port %x\n", key.inport);
  LL_DBG_PRINTK("[FW4] daddr %x\n", key.daddr);
  LL_DBG_PRINTK("[FW4] saddr %d\n", key.saddr);
  LL_DBG_PRINTK("[FW4] sport %d\n", key.sport);
  LL_DBG_PRINTK("[FW4] dport %d\n", key.dport);
  LL_DBG_PRINTK("[FW4] l4proto %d\n", key.l4proto);

  xf->pm.table_id = LL_DP_FW4_MAP;

  idx = xf->pm.fw_lid;

  for (i = 0; i < DP_MAX_LOOPS_PER_FWLKUP; i++) {

    fwe = bpf_map_lookup_elem(&fw_v4_map, &idx);
    if (!fwe) {
      LL_DBG_PRINTK("[FW4] miss");
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
      RETURN_TO_MP();
      return DP_DROP;
    } else {
      if (idx == 0) {
        xf->pm.fw_mid = fwe->v.nr;
      }

      if (fwe->v.zone != 0 && 
        (key.inport & fwe->m.inport) == fwe->v.inport &&
        (key.daddr & fwe->m.daddr) == fwe->v.daddr &&
        (key.saddr & fwe->m.saddr) == fwe->v.saddr &&
        (key.sport & fwe->m.sport) == fwe->v.sport &&
        (key.dport & fwe->m.dport) == fwe->v.dport &&
        (key.l4proto & fwe->m.l4proto) == fwe->v.l4proto) {

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
        xf->pm.fw_lid >= xf->pm.fw_mid) {
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
      bpf_printk("[FW4] -- done");
      RETURN_TO_MP();
      return DP_DROP;
    }
  }

  xf->pm.phit |= LLB_DP_FW_HIT;

  /* This condition should never hit */
  if (!fwe) return 0;

  act = &fwe->fwa;

  if (act->ca.act_type == DP_SET_NOP) {
    goto done;
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;
    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_FW_RDR);
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROP(xf);
  }

  xf->pm.phit |= LLB_DP_RES_HIT;

done:
  dp_do_map_stats(ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.cidx);

  RETURN_TO_MP();
  return DP_DROP;
}

static int __always_inline
dp_do_fw_main(void *ctx, struct xfi *xf)
{
  return dp_do_fw4_main(ctx, xf);
}

