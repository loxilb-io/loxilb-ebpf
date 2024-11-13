/*
 *  llb_kern_ct.c: Loxilb kernel eBPF ConnTracking Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#ifdef HAVE_LEGACY_BPF_MAPS

struct bpf_map_def SEC("maps") ct_ctr = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_ct_ctrtact),
  .max_entries = 1 
};

#else

struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} ct_ctr SEC(".maps");

#endif

#define CT_KEY_GEN(k, xf)                    \
do {                                         \
  (k)->daddr[0] = xf->l34m.daddr[0];         \
  (k)->daddr[1] = xf->l34m.daddr[1];         \
  (k)->daddr[2] = xf->l34m.daddr[2];         \
  (k)->daddr[3] = xf->l34m.daddr[3];         \
  (k)->saddr[0] = xf->l34m.saddr[0];         \
  (k)->saddr[1] = xf->l34m.saddr[1];         \
  (k)->saddr[2] = xf->l34m.saddr[2];         \
  (k)->saddr[3] = xf->l34m.saddr[3];         \
  (k)->sport = xf->l34m.source;              \
  (k)->dport = xf->l34m.dest;                \
  (k)->l4proto = xf->l34m.nw_proto;          \
  (k)->zone = xf->pm.zone;                   \
  (k)->v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0; \
  (k)->ident = xf->tm.tun_decap ? 0 : xf->tm.tunnel_id;      \
  (k)->type = xf->tm.tun_decap ? 0 : xf->tm.tun_type;        \
}while(0)

#define dp_run_ctact_helper(x, a) \
do {                              \
  switch ((a)->ca.act_type) {     \
  case DP_SET_NOP:                \
  case DP_SET_SNAT:               \
  case DP_SET_DNAT:               \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = (x)->l34m.seq;   \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = (x)->l34m.ack;   \
    break;                        \
  default:                        \
    break;                        \
  }                               \
} while(0)

static int __always_inline
dp_run_ct_helper(struct xfi *xf)
{
  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  act = bpf_map_lookup_elem(&ct_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[FCH4] miss");
    return -1;
  }

  /* We dont do much strict tracking after EST state.
   * But need to maintain minimal ctinfo
   */
  dp_run_ctact_helper(xf, act);
  return 0;
}

#ifdef HAVE_DP_EXTCT
#define DP_RUN_CT_HELPER(x)                \
do {                                       \
  if ((x)->l34m.nw_proto == IPPROTO_TCP) { \
    dp_run_ct_helper(x);                   \
  }                                        \
} while(0)
#else
#define DP_RUN_CT_HELPER(x)
#endif

static __u32 __always_inline
dp_ct_get_newctr(__u32 *nid)
{
  __u32 k = 0;
  __u32 v = 0;
  struct dp_ct_ctrtact *ctr;

  ctr = bpf_map_lookup_elem(&ct_ctr, &k);

  if (ctr == NULL) {
    return 0;
  }

  *nid = ctr->start;
  /* FIXME - We can potentially do a percpu array and do away
   *         with the locking here
   */ 
  bpf_spin_lock(&ctr->lock);
  v = ctr->counter;
  ctr->counter += 2;
  if (ctr->counter >= ctr->entries) {
    ctr->counter = ctr->start;
  }
  bpf_spin_unlock(&ctr->lock);

  return v;
}

static int __always_inline
dp_ct_proto_xfk_init(struct dp_ct_key *key,
                     nxfrm_inf_t *xi,
                     struct dp_ct_key *xkey,
                     nxfrm_inf_t *xxi)
{
  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport; 
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;
  xkey->ident = key->ident;
  xkey->type = key->type;

  if (xi->dsr) {
    if (xi->nat_flags & LLB_NAT_DST) {
      xxi->nat_flags = LLB_NAT_SRC;
      DP_XADDR_CP(xxi->nat_xip, key->daddr);
      xxi->nat_xport = key->dport;
      xxi->nv6 = xi->nv6;
    }
    xxi->dsr = xi->dsr;
    return 0;
  }

  /* Apply NAT xfrm if needed */
  if (xi->nat_flags & LLB_NAT_DST) {
    xkey->v6 = (__u8)(xi->nv6);
    DP_XADDR_CP(xkey->saddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->daddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->saddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
        if (xi->nat_xport)
          xkey->sport = xi->nat_xport;
        else
          xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_SRC;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->daddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_SRC) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->daddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->saddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->daddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_DST;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->saddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }
  if (xi->nat_flags & LLB_NAT_HDST) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
      else
        xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_HSRC;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_HSRC) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_HDST;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);

    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }

  return 0;  
}

static int __always_inline
dp_ct3_sm(struct dp_ct_dat *tdat,
          struct dp_ct_dat *xtdat,
          ct_dir_t dir)
{
  ct_state_t new_state = tdat->pi.l3i.state;
  switch (tdat->pi.l3i.state) {
  case CT_STATE_NONE:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_REQ;
    } else {
      return -1;
    }
    break;
  case CT_STATE_REQ:
    if (dir == CT_DIR_OUT)  {
      new_state = CT_STATE_REP;
    }
    break;
  case CT_STATE_REP:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_EST;
    } 
    break;
  default:
    break;
  }

  tdat->pi.l3i.state = new_state;

  if (new_state == CT_STATE_EST) {
    return 1;
  }

  return 0;
}

static int __always_inline
dp_ct_tcp_sm(void *ctx, struct xfi *xf, 
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_tcp_pinf_t *ts = &tdat->pi.t;
  ct_tcp_pinf_t *rts = &xtdat->pi.t;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct tcphdr *t = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint8_t tcp_flags = xf->pm.tcp_flags;
  ct_tcp_pinfd_t *td = &ts->tcp_cts[dir];
  ct_tcp_pinfd_t *rtd;
  uint32_t seq;
  uint32_t ack;
  uint32_t nstate = 0;

  if (t + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  seq = bpf_ntohl(t->seq);
  ack = bpf_ntohl(t->ack_seq);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pi.t.tcp_cts[0].pseq = t->seq;
    tdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pi.t.tcp_cts[0].pseq = t->seq;
    xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT:CT_DIR_IN];

  if (tcp_flags & LLB_TCP_RST) {
    nstate = CT_TCP_CW;
    goto end;
  }

  switch (ts->state) {
  case CT_TCP_CLOSED:

    if (xf->nm.dsr) {
      nstate = CT_TCP_EST;
      goto end;
    }

    /* If DP starts after TCP was established
     * we need to somehow handle this particular case
     */
    if (tcp_flags & LLB_TCP_ACK)  {
      td->seq = seq;
      if (td->init_acks) {
        if (ack  > rtd->seq + 2) {
          nstate = CT_TCP_ERR;
          goto end;
        }
      }
      td->init_acks++;
      if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD &&
          rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {
        nstate = CT_TCP_EST;
        break;
      }
      nstate = CT_TCP_ERR;
      goto end;
    }
    
    if ((tcp_flags & LLB_TCP_SYN) != LLB_TCP_SYN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    /* SYN sent with ack 0 */
    if (ack != 0 && dir != CT_DIR_IN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SS;
    break;
  case CT_TCP_SS:
    if (dir != CT_DIR_OUT) {
      if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
        td->seq = seq;
        nstate = CT_TCP_SS;
      } else {
        nstate = CT_TCP_ERR;
      }
      goto end;
    }
  
    if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
      nstate = CT_TCP_ERR;
      goto end;
    }
  
    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SA;
    break;

  case CT_TCP_SA:
    if (dir != CT_DIR_IN) {
      if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      if (ack  != rtd->seq + 1) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      nstate = CT_TCP_SA;
      goto end;
    } 

    if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
      td->seq = seq;
      nstate = CT_TCP_SS;
      goto end;
    }
  
    if ((tcp_flags & LLB_TCP_ACK) != LLB_TCP_ACK) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_EST;
    break;

  case CT_TCP_EST:
    if (tcp_flags & LLB_TCP_FIN) {
      ts->fndir = dir;
      nstate = CT_TCP_FINI;
      td->seq = seq;
    } else {
      nstate = CT_TCP_EST;
    }
    break;

  case CT_TCP_FINI:
    if (ts->fndir != dir) {
      if ((tcp_flags & (LLB_TCP_FIN|LLB_TCP_ACK)) == 
          (LLB_TCP_FIN|LLB_TCP_ACK)) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      } else if (tcp_flags & LLB_TCP_ACK) {
        nstate = CT_TCP_FINI2;
        td->seq = seq;
      }
    }
    break;
  case CT_TCP_FINI2:
    if (ts->fndir != dir) {
      if (tcp_flags & LLB_TCP_FIN) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      }
    }
    break;

  case CT_TCP_FINI3:
    if (ts->fndir == dir) {
      if (tcp_flags & LLB_TCP_ACK) {
        nstate = CT_TCP_CW;
      }
    }
    break;

  default:
    break;
  }

end:
  ts->state = nstate;
  rts->state = nstate;

  if (nstate != CT_TCP_ERR && dir == CT_DIR_OUT) {
    xtdat->pi.t.tcp_cts[0].seq = seq;
  }

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_TCP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_TCP_CW) {
    return CT_SMR_CTD;
  } else if (nstate & CT_TCP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_TCP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_udp_sm(void *ctx, struct xfi *xf,
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_udp_pinf_t *us = &tdat->pi.u;
  ct_udp_pinf_t *xus = &xtdat->pi.u;
  uint32_t nstate = us->state;

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
    us->pkts_seen++;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
    us->rpkts_seen++;
  }

  switch (us->state) {
  case CT_UDP_CNI:

    if (xf->nm.dsr || xf->l2m.ssnid) {
      nstate = CT_UDP_EST;
      break;
    }

    if (us->pkts_seen && us->rpkts_seen) {
      nstate = CT_UDP_EST;
    } else if (us->pkts_seen > CT_UDP_CONN_THRESHOLD) {
      nstate = CT_UDP_UEST;
    }

    break;
  case CT_UDP_UEST:
    if (us->rpkts_seen || us->pkts_seen > 2*CT_UDP_CONN_THRESHOLD)
      nstate = CT_UDP_EST;
    break;
  case CT_UDP_EST:
    if (xf->pm.l4fin) {
      nstate = CT_UDP_FINI;
      us->fndir = dir;
    }
    break;
  case CT_UDP_FINI:
    if (xf->pm.l4fin && us->fndir != dir) {
      nstate = CT_UDP_CW;
    }
    break;
  default:
    break;
  }

  us->state = nstate;
  xus->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_UDP_UEST)
    return CT_SMR_UEST;
  else if (nstate == CT_UDP_EST)
    return CT_SMR_EST;
  else if (nstate & CT_UDP_CW)
    return CT_SMR_CTD;
  else if (nstate & CT_UDP_FIN_MASK)
    return CT_SMR_FIN;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp6_sm(void *ctx, struct xfi *xf,
               struct dp_ct_tact *atdat,
               struct dp_ct_tact *axtdat,
               ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmp6hdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->icmp6_dataun.u_echo.sequence);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->icmp6_type) {
  case ICMPV6_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMPV6_TIME_EXCEED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMPV6_ECHO_REPLY:
  case ICMPV6_ECHO_REQUEST:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  }

  switch (is->state) {
  case CT_ICMP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }
    if (i->icmp6_type != ICMPV6_ECHO_REQUEST) {
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->icmp6_type == ICMPV6_ECHO_REQUEST) {
      is->lseq = seq;
    } else if (i->icmp6_type == ICMPV6_ECHO_REPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_icmp_sm(void *ctx, struct xfi *xf, 
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmphdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->un.echo.sequence);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->type) {
  case ICMP_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMP_TIME_EXCEEDED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMP_REDIRECT:
    is->state |= CT_ICMP_RDR;
    goto end;
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  } 

  switch (is->state) { 
  case CT_ICMP_CLOSED: 
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }

    if (i->type != ICMP_ECHO) { 
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->type == ICMP_ECHO) {
      is->lseq = seq;
    } else if (i->type == ICMP_ECHOREPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_sctp_sm(void *ctx, struct xfi *xf, 
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_sctp_pinf_t *ss = &tdat->pi.s;
  ct_sctp_pinf_t *xss = &xtdat->pi.s;
  ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
  ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];
  uint32_t nstate = 0;
  uint32_t npmhh = tdat->pi.npmhh;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct sctphdr *s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  struct sctp_dch *c;
  struct sctp_init_ch *ic;
  struct sctp_cookie *ck;
  struct sctp_param  *pm;
  uint16_t poff = 0;
  uint32_t nh = 0;
  int i = 0;

  if (s + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
  
  if (c + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
    return -1;
  }

  poff = xf->pm.l4_off + sizeof(*s);

  nstate = ss->state;
  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    atdat->ctd.pb.bytes += xf->pm.l3_len;
    atdat->ctd.pb.packets += 1;
  } else {
    axtdat->ctd.pb.bytes += xf->pm.l3_len;
    axtdat->ctd.pb.packets += 1;
  }

  switch (c->type) {
  case SCTP_ERROR:
    nstate = CT_SCTP_ERR;
    goto end;
  case SCTP_SHUT:
    nstate = CT_SCTP_SHUT;
    goto end;
  case SCTP_ABORT:
    nstate = CT_SCTP_ABRT;
    goto end;
  }

  switch (ss->state) {
  case CT_SCTP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_SCTP_EST;
      goto end;
    }

    if (c->type != SCTP_INIT_CHUNK || dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      goto end;
    }
    poff += sizeof(*c);

    ss->itag = ic->tag;
    nstate = CT_SCTP_INIT;

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      goto add_nph0;
    } 
    poff += sizeof(*ic);

    if (xf->l2m.dl_type != bpf_ntohs(ETH_P_IP) || !tdat->xi.nat_flags) {
      break;
    }

    pss->mh_host[0] = xf->l34m.saddr[0];
    pss->nh = 1;
    pss->odst = xf->l34m.daddr[0];
    pss->osrc = xf->l34m.saddr[0];

    nh = 1;
    for (i = 0; i < LLB_MAX_SCTP_CHUNKS_INIT; i++) {
      uint16_t csz = 0;
      if (poff >= 4096) {
        bpf_spin_unlock(&atdat->lock);
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        return -1;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(DP_PDATA(ctx), poff));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        goto add_nph0;
      }

      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }
        if (nh <= LLB_MAX_MHOSTS && *ip != pss->osrc) {
          pss->mh_host[nh] = *ip;
          pss->nh++;
          nh++;
        }

        if (!atdat->nat_act.nv6) {
          /* Checksum to be taken care of at a later stage */
          if (nh-1 < LLB_MAX_MHOSTS && atdat->ctd.pi.pmhh[nh-1] != 0) {
            *ip = atdat->ctd.pi.pmhh[nh-1];
          } else if (atdat->ctd.pi.pmhh[0] != 0) {
            *ip = atdat->ctd.pi.pmhh[0];
          } else if (atdat->nat_act.rip[0] != 0) {
            *ip = atdat->nat_act.rip[0];
          }
        }
      }

      csz = bpf_ntohs(pm->len);
      poff += (csz + 3) & ~0x3;
    }

add_nph0:
    if ((pss->nh - 1) < npmhh) {
      int grow;
      int diff = npmhh - pss->nh + 1;

      grow = ((diff)*(sizeof(*pm)+sizeof(__u32)));
      poff = (((struct __sk_buff *)ctx)->len);

      bpf_spin_unlock(&atdat->lock);
      if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        bpf_spin_lock(&atdat->lock);
        break;
      }
      bpf_spin_lock(&atdat->lock);

      pm = DP_TC_PTR(DP_PDATA(ctx));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        break;
      }

      for (i = 0; i < diff; i++) {

        if (i >= LLB_MAX_MHOSTS) break;

        /* Keep the verifier happy */
        if (poff > SCTP_MAX_INIT_ACK_SZ) {
          break;
        }

        pm = DP_ADD_PTR(pm, poff);
        if (pm + 1 > dend) {
          break;
        }

        pm->type = bpf_htons(SCTP_IPV4_ADDR_PARAM);
        pm->len = bpf_htons(sizeof(*pm) + sizeof(__u32));

        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        if (!atdat->nat_act.nv6) {
          /* Checksum to be taken care of at a later stage */
          if (i < LLB_MAX_MHOSTS && atdat->ctd.pi.pmhh[i] != 0) {
            *ip = atdat->ctd.pi.pmhh[i];
          } else if (atdat->ctd.pi.pmhh[0] != 0) {
            *ip = atdat->ctd.pi.pmhh[0];
          } else if (atdat->nat_act.rip[0] != 0) {
            *ip = atdat->nat_act.rip[0];
          }
        }

        poff = sizeof(*pm)+sizeof(__u32);
      }

      s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
      if (s + 1 > dend) {
        break;
      }

      c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
      if (c + 1 > dend) {
        break;
      }

      poff = bpf_ntohs(c->len) + grow;
      c->len = bpf_htons(poff);
      xf->pm.l3_adj = grow;
    }
    break;
  case CT_SCTP_INIT:

    if (c->type != SCTP_INIT_CHUNK && c->type != SCTP_INIT_CHUNK_ACK) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if ((c->type == SCTP_INIT_CHUNK && dir != CT_DIR_IN) ||
        (c->type == SCTP_INIT_CHUNK_ACK && dir != CT_DIR_OUT)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      goto end;
    }
    poff += sizeof(*c);

    if (c->type == SCTP_INIT_CHUNK) {
      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
    } else {
      if (s->vtag != ss->itag) {
        nstate = CT_SCTP_ERR;
        goto end;
      }

      ss->otag = ic->tag;
      nstate = CT_SCTP_INITA;
    }

    if (xf->l2m.dl_type != bpf_ntohs(ETH_P_IP) || !tdat->xi.nat_flags) {
      break;
    }

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      goto add_nph1;
    }
    poff += sizeof(*ic);

    pxss->mh_host[0] = xf->l34m.saddr[0];
    pxss->nh = 1;
    pxss->odst = xf->l34m.daddr[0];
    pxss->osrc = xf->l34m.saddr[0];

    nh = 1;
    for (i = 0; i < LLB_MAX_SCTP_CHUNKS_INIT; i++) {
      uint16_t csz = 0;
      if (poff >= 4096) {
        bpf_spin_unlock(&atdat->lock);
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        return -1;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(DP_PDATA(ctx), poff));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        goto add_nph1;
      }

      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        if (nh <= LLB_MAX_MHOSTS && *ip != pxss->osrc) {
          pxss->mh_host[nh] = *ip;
          pxss->nh++;
          nh++;
        }

        if (!axtdat->nat_act.nv6) {
          /* Checksum to be taken care of a later stage */
          if (nh - 1 < LLB_MAX_MHOSTS && axtdat->ctd.pi.pmhh[nh-1] != 0) {
            *ip = axtdat->ctd.pi.pmhh[nh-1];
          } else if (axtdat->ctd.pi.pmhh[0] != 0) {
            *ip = axtdat->ctd.pi.pmhh[0];
          } else if (axtdat->nat_act.xip[0] != 0) {
            *ip = axtdat->nat_act.xip[0];
          }
        }
      }

      csz = bpf_ntohs(pm->len);
      poff += (csz + 3) & ~0x3;
    }

add_nph1:
    if ((pxss->nh - 1) < npmhh) {
      int grow;
      int diff = npmhh - pxss->nh + 1;

      grow = ((diff)*(sizeof(*pm)+sizeof(__u32)));
      poff = (((struct __sk_buff *)ctx)->len);

      bpf_spin_unlock(&atdat->lock);
      if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
        bpf_spin_lock(&atdat->lock);
        break;
      }
      bpf_spin_lock(&atdat->lock);

      pm = DP_TC_PTR(DP_PDATA(ctx));
      dend = DP_TC_PTR(DP_PDATA_END(ctx));
      if (pm + 1 > dend) {
        break;
      }

      for (i = 0; i < diff; i++) {

        if (i >= LLB_MAX_MHOSTS) break;

        /* Keep the verifier happy */
        if (poff > SCTP_MAX_INIT_ACK_SZ) {
          break;
        }

        pm = DP_ADD_PTR(pm, poff);
        if (pm + 1 > dend) {
          break;
        }

        pm->type = bpf_htons(SCTP_IPV4_ADDR_PARAM);
        pm->len = bpf_htons(sizeof(*pm)+sizeof(__u32));

        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }

        /* Checksum to be taken care of at a later stage */
        if (i < LLB_MAX_MHOSTS && axtdat->ctd.pi.pmhh[i] != 0) {
          *ip = axtdat->ctd.pi.pmhh[i];
        } else if (axtdat->ctd.pi.pmhh[0] != 0) {
          *ip = axtdat->ctd.pi.pmhh[0];
        } else if (axtdat->nat_act.xip[0] != 0) {
          *ip = axtdat->nat_act.xip[0];
        }

        poff = sizeof(*pm)+sizeof(__u32);
      }

      s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
      if (s + 1 > dend) {
        break;
      }

      c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
      if (c + 1 > dend) {
        break;
      }

      poff = bpf_ntohs(c->len) + grow;
      c->len = bpf_htons(poff);
      xf->pm.l3_adj = grow;
    }

    if (npmhh > 0) {
      tdat->xi.mhon =  1;
      xtdat->xi.mhon = 1;
    }
    break;
  case CT_SCTP_INITA:

    if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) &&
        (c->type != SCTP_COOKIE_ECHO && dir != CT_DIR_IN)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (c->type == SCTP_INIT_CHUNK) {
      ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
      if (ic + 1 > dend) {
        goto end;
      }

      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
      goto end;
    }

    ck = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ck + 1 > dend) {
      goto end;
    }

    if (ss->otag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ss->cookie = ck->cookie;
    nstate = CT_SCTP_COOKIE;
    break;
  case CT_SCTP_COOKIE:
    if (c->type != SCTP_COOKIE_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (ss->itag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    nstate = CT_SCTP_COOKIEA;
    break;
  case CT_SCTP_COOKIEA:
    nstate = CT_SCTP_EST;
    break;
  case CT_SCTP_PRE_EST:
    if (dir != CT_DIR_OUT) {
      nstate = CT_SCTP_EST;
    }
    break;
  case CT_SCTP_EST:
#ifdef HAVE_SCTPMH_HB_MANGLE
    if (pss->nh) {
      int grow;
      poff = (((struct __sk_buff *)ctx)->len);
      if (c->type == SCTP_HB_REQ) {
        grow = sizeof(__u32);
        bpf_spin_unlock(&atdat->lock);
        if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          bpf_spin_lock(&atdat->lock);
          break;
        }

        bpf_spin_lock(&atdat->lock);
        dend = DP_TC_PTR(DP_PDATA_END(ctx));
        s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

        if (s + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));

        if (c + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        pm = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
        if (pm + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        __u16 pmlen = bpf_ntohs(pm->len);
        if (pmlen > 512) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __be32 *ip = DP_ADD_PTR(pm, pmlen);
        if (ip + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }

        *ip = xf->l34m.saddr[0];
        c->len = bpf_htons((bpf_ntohs(c->len) + 4));
        pm->len = bpf_htons((bpf_ntohs(pm->len) + 4));
        xf->pm.l3_adj = grow;
      } else if (c->type == SCTP_HB_ACK) {
        pm = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
        if (pm + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __u16 pmlen = bpf_ntohs(pm->len);
        if (pmlen > 512) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        __be32 *ip = DP_ADD_PTR(pm, pmlen-4);
        if (ip + 1 > dend) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          break;
        }
        c->len = bpf_htons((bpf_ntohs(c->len) - 4));
        pm->len = bpf_htons((bpf_ntohs(pm->len) - 4));

        if (dir == CT_DIR_IN) {
          xf->nm.nxip4 = *ip;
        } else {
          if (xf->nm.nrip4) {
            xf->nm.nrip4 = *ip;
          }
        }

        grow = -4;
        bpf_spin_unlock(&atdat->lock);
        if (dp_pktbuf_expand_tail(ctx, grow + poff) < 0) {
          LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLCT_ERR);
          bpf_spin_lock(&atdat->lock);
          break;
        }
        bpf_spin_lock(&atdat->lock);

        xf->pm.l3_adj = grow;
      }
    }
#endif
    break;
  case CT_SCTP_ABRT:
    nstate = CT_SCTP_ABRT;
    break;
  case CT_SCTP_SHUT:
    if (c->type != SCTP_SHUT_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTA;
    break;
  case CT_SCTP_SHUTA:
    if (c->type != SCTP_SHUT_COMPLETE && dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTC;
    break;
  default:
    break;
  }
end:

  if (pss->nh && nstate == CT_SCTP_COOKIE) {
    nstate = CT_SCTP_EST;
  }
  ss->state = nstate;
  xss->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_SCTP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_SCTP_SHUTC) {
    return CT_SMR_CTD;
  } else if (nstate & CT_SCTP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_SCTP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

static int __always_inline
dp_ct_sm(void *ctx, struct xfi *xf,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat,
         ct_dir_t dir)
{
  int sm_ret = 0;

  switch (xf->l34m.nw_proto) {
  case IPPROTO_TCP:
    sm_ret = dp_ct_tcp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_UDP:
    sm_ret = dp_ct_udp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMP:
    sm_ret = dp_ct_icmp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_SCTP:
    sm_ret = dp_ct_sctp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMPV6:
    sm_ret = dp_ct_icmp6_sm(ctx, xf, atdat, axtdat, dir);
    break;
  default:
    sm_ret = CT_SMR_UNT;
    break;
  }

  return sm_ret;
}

#define CP_CT_NAT_TACTS(dst, src)  \
  memcpy(&dst->ca, &src->ca, sizeof(struct dp_cmn_act));  \
  memcpy(&dst->ctd, &src->ctd, sizeof(struct dp_ct_dat)); \
  dst->ito =  src->ito; \
  dst->lts =  src->lts; \
  memcpy(&dst->nat_act, &src->nat_act, sizeof(struct dp_nat_act)); \

static int __always_inline
dp_ct_est(struct xfi *xf,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  //struct dp_ct_dat *xtdat = &axtdat->ctd;
  struct dp_ct_tact *adat, *axdat;
  ct_sctp_pinf_t *ss;
  ct_sctp_pinf_t *tss;
  int i, j, k;

  k = 0;
  adat = bpf_map_lookup_elem(&xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&xctk, &k);

  if (adat == NULL || axdat == NULL || tdat->xi.dsr || tdat->xi.nv6) {
    return 0;
  }

  CP_CT_NAT_TACTS(adat, atdat);
  CP_CT_NAT_TACTS(axdat, axtdat);

  ss = &adat->ctd.pi.s;
  tss = &atdat->ctd.pi.s;

  switch (xf->l34m.nw_proto) {
  case IPPROTO_UDP:
    if (xf->l2m.ssnid) {
      if (xf->pm.dir == CT_DIR_IN) {
        adat->ctd.xi.osp = key->sport;
        adat->ctd.xi.odp = key->dport;
        key->sport = xf->l2m.ssnid;
        key->dport = xf->l2m.ssnid;
        adat->ctd.pi.frag = 1;
        bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
      } else {
        axdat->ctd.xi.osp = xkey->sport;
        axdat->ctd.xi.odp = xkey->dport;
        xkey->sport = xf->l2m.ssnid;
        xkey->dport = xf->l2m.ssnid;
        axdat->ctd.pi.frag = 1;
        bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);
      }
    }
    break;
  case IPPROTO_SCTP:
    /* Ignore Hearbeats */
    if (xf->pm.goct) return 0;

    if (tdat->xi.mhon && xf->pm.dir == CT_DIR_IN) {
      __be32 primary_src = 0;
      __be32 primary_ep = 0;
      __be32 secondary_ep = 0;
      __be32 mhvip = 0;
      ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
      //ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];
      ct_sctp_pinfd_t *tpxss = &tss->sctp_cts[CT_DIR_OUT];

      for (i = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        if (pss->mh_host[i] == xf->l34m.saddr[0]) {
          primary_ep = tpxss->osrc;
          break;
        }
      }

      if (!primary_ep) {
        break;
      }

      adat->ctd.xi.mhon = 0;
      axdat->ctd.xi.mhon = 0;
      adat->ctd.xi.mhs = 1;
      axdat->ctd.xi.mhs = 1;

      for (i = 1, j = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        j = i - 1;
        if (j < LLB_MAX_MHOSTS) {
          if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
            mhvip = tdat->pi.pmhh[j];
            primary_src = pss->mh_host[i];
            if (tpxss->mh_host[i]) {
              secondary_ep = tpxss->mh_host[i];
            } else {
              secondary_ep = primary_ep;
            }

            key->saddr[0] = pss->mh_host[i];
            key->daddr[0] = mhvip;

            adat->ctd.xi.nat_rip[0] = mhvip;
            adat->nat_act.rip[0] = mhvip;
            adat->ctd.xi.nat_xip[0] = secondary_ep;
            adat->nat_act.xip[0] = secondary_ep;

            xkey->daddr[0] = mhvip;
            xkey->saddr[0] = secondary_ep;
            axdat->ctd.xi.nat_xip[0] = mhvip;
            axdat->nat_act.xip[0] = mhvip;

            LL_DBG_PRINTK("[CTRK] xASSOC %d 0x%x->0x%x", i, key->saddr[0], key->daddr[0]);
            axdat->nat_act.rip[0] = primary_src;
            axdat->ctd.xi.nat_rip[0] = primary_src;
            bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);

            LL_DBG_PRINTK("[CTRK] ASSOC 0x%x->0x%x",key->saddr[0], key->daddr[0]);
            bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
          }
        }
      }

      j = i-1;
      i = 0;
      for (;j < LLB_MAX_MHOSTS; j++) {
        if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
          mhvip = tdat->pi.pmhh[j];
          primary_src = pss->mh_host[i];
          if (tpxss->mh_host[i]) {
            secondary_ep = tpxss->mh_host[i];
          } else {
            secondary_ep = primary_ep;
          }

          key->saddr[0] = pss->mh_host[i];
          key->daddr[0] = mhvip;

          adat->ctd.xi.nat_rip[0] = mhvip;
          adat->nat_act.rip[0] = mhvip;
          adat->ctd.xi.nat_xip[0] = secondary_ep;
          adat->nat_act.xip[0] = secondary_ep;

          xkey->daddr[0] = mhvip;
          xkey->saddr[0] = secondary_ep;
          axdat->ctd.xi.nat_xip[0] = mhvip;
          axdat->nat_act.xip[0] = mhvip;

          LL_DBG_PRINTK("[CTRK] xASSOC %d 0x%x->0x%x", i, key->saddr[0], key->daddr[0]);
          axdat->nat_act.rip[0] = primary_src;
          axdat->ctd.xi.nat_rip[0] = primary_src;
          bpf_map_update_elem(&ct_map, xkey, axdat, BPF_ANY);

          LL_DBG_PRINTK("[CTRK] ASSOC 0x%x->0x%x",key->saddr[0], key->daddr[0]);
          bpf_map_update_elem(&ct_map, key, adat, BPF_ANY);
        }
      }
    }
    break;
  default:
    break;
  }
  return 0;
}

static int __always_inline
dp_ct_ctd(struct xfi *xf,
         struct dp_ct_key *key,
         struct dp_ct_key *xkey,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_sctp_pinf_t *ss;
  int i,j;

  ss = &atdat->ctd.pi.s;

  switch (xf->l34m.nw_proto) {
  case IPPROTO_SCTP:
    if (xf->nm.npmhh) {
      ct_sctp_pinfd_t *pss = &ss->sctp_cts[CT_DIR_IN];
      ct_sctp_pinfd_t *pxss = &ss->sctp_cts[CT_DIR_OUT];

      for (i = 0; i < pss->nh && i < LLB_MAX_MHOSTS; i++) {
        key->saddr[0] = pss->mh_host[i];
        for (j = 0; j < LLB_MAX_MHOSTS; j++) {
          if (tdat->pi.pmhh[j] && pss->mh_host[i]) {
            key->daddr[0] = tdat->pi.pmhh[j];
            xkey->daddr[0] = tdat->pi.pmhh[j];

            bpf_map_delete_elem(&ct_map, key);
            bpf_map_delete_elem(&ct_map, xkey);
          }
        }
        key->daddr[0] = pss->odst;
        bpf_map_delete_elem(&ct_map, key);
      }

      for (i = 0; i < pxss->nh && i < LLB_MAX_MHOSTS; i++) {
        xkey->saddr[0] = pxss->mh_host[i];
        for (j = 0; j < LLB_MAX_MHOSTS; j++) {
          if (xtdat->pi.pmhh[j] && pxss->mh_host[i]) {
            xkey->daddr[0] = xtdat->pi.pmhh[j];
            bpf_map_delete_elem(&ct_map, xkey);
          }
        }
        xkey->daddr[0] = pxss->odst;
        bpf_map_delete_elem(&ct_map, xkey);

      }
    }
    break;
  default:
    break;
  }
  return 0;
}

static int __always_inline
dp_ct_in(void *ctx, struct xfi *xf)
{
  struct dp_ct_key key;
  struct dp_ct_key xkey;
  struct dp_ct_tact *adat;
  struct dp_ct_tact *axdat;
  struct dp_ct_tact *atdat;
  struct dp_ct_tact *axtdat;
  nxfrm_inf_t *xi;
  nxfrm_inf_t *xxi;
  ct_dir_t cdir = CT_DIR_IN;
  int smr = CT_SMR_ERR;
  int k;

  k = 0;
  adat = bpf_map_lookup_elem(&xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&xctk, &k);

  if (adat == NULL || axdat == NULL) {
    return smr;
  }

  xi = &adat->ctd.xi;
  xxi = &axdat->ctd.xi;
 
  /* CT Key */
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  DP_XADDR_CP(key.saddr, xf->l34m.saddr);
  key.sport = xf->l34m.source;
  key.dport = xf->l34m.dest;
  key.l4proto = xf->l34m.nw_proto;
  key.zone = xf->pm.zone;
  key.v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0;
  key.ident = xf->tm.tun_decap ? 0 : xf->tm.tunnel_id;
  key.type = xf->tm.tun_decap ? 0 : xf->tm.tun_type;

  if (key.l4proto != IPPROTO_TCP &&
      key.l4proto != IPPROTO_UDP &&
      key.l4proto != IPPROTO_ICMP &&
      key.l4proto != IPPROTO_SCTP &&
      key.l4proto != IPPROTO_ICMPV6) {
    return 0;
  }

  xi->nat_flags = xf->pm.nf;
  DP_XADDR_CP(xi->nat_xip, xf->nm.nxip);
  DP_XADDR_CP(xi->nat_rip, xf->nm.nrip);
  xi->nat_xport = xf->nm.nxport;
  xi->nv6 = xf->nm.nv6;
  xi->dsr = xf->nm.dsr;

  xxi->nat_flags = 0;
  xxi->nat_xport = 0;
  DP_XADDR_SETZR(xxi->nat_xip);
  DP_XADDR_SETZR(xxi->nat_rip);

  if (xf->pm.nf & (LLB_NAT_DST|LLB_NAT_SRC)) {
    if (DP_XADDR_ISZR(xi->nat_xip)) {
      if (xf->pm.nf == LLB_NAT_DST) {
        xi->nat_flags = LLB_NAT_HDST;
      } else if (xf->pm.nf == LLB_NAT_SRC){
        xi->nat_flags = LLB_NAT_HSRC;
      }
    }
  }

  dp_ct_proto_xfk_init(&key, xi, &xkey, xxi);

  atdat = bpf_map_lookup_elem(&ct_map, &key);
  axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
  if (atdat == NULL || axtdat == NULL) {

    LL_DBG_PRINTK("[CTRK] new-ct4");
    adat->ca.ftrap = 0;
    adat->ca.oaux = 0;
    adat->ca.cidx = dp_ct_get_newctr(&adat->ctd.nid);
    adat->ca.fwrid = xf->pm.fw_rid;
    adat->ca.record = xf->pm.dp_rec;
    memset(&adat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xi->nat_flags) {
      adat->ca.act_type = xi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(adat->nat_act.xip,  xi->nat_xip);
      DP_XADDR_CP(adat->nat_act.rip, xi->nat_rip);
      adat->nat_act.xport = xi->nat_xport;
      adat->nat_act.doct = 1;
      adat->nat_act.rid = xf->pm.rule_id;
      adat->nat_act.aid = xf->nm.sel_aid;
      adat->nat_act.nv6 = xf->nm.nv6 ? 1:0;
      adat->nat_act.dsr = xf->nm.dsr;
      adat->nat_act.cdis = xf->nm.cdis;
      adat->nat_act.nmh = xf->nm.npmhh;
      adat->ito = xf->nm.ito;
    } else {
      adat->ito = 0;
      adat->ca.act_type = DP_SET_DO_CT;
    }
    adat->ctd.dir = cdir;

    /* FIXME This is duplicated data */
    adat->ctd.rid = xf->pm.rule_id;
    adat->ctd.aid = xf->nm.sel_aid;
    adat->ctd.smr = CT_SMR_INIT;
    adat->ctd.pi.npmhh = xf->nm.npmhh;
    adat->ctd.pi.pmhh[0] = xf->nm.pmhh[0];
    adat->ctd.pi.pmhh[1] = xf->nm.pmhh[1];
    adat->ctd.pi.pmhh[2] = xf->nm.pmhh[2]; // LLB_MAX_MHOSTS
    adat->ctd.pb.bytes = 0;
    adat->ctd.pb.packets = 0;

    axdat->ca.ftrap = 0;
    axdat->ca.oaux = 0;
    axdat->ca.cidx = adat->ca.cidx + 1;
    axdat->ca.fwrid = xf->pm.fw_rid;
    axdat->ca.record = xf->pm.dp_rec;
    memset(&axdat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xxi->nat_flags) { 
      axdat->ca.act_type = xxi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(axdat->nat_act.xip, xxi->nat_xip);
      DP_XADDR_CP(axdat->nat_act.rip, xxi->nat_rip);
      axdat->nat_act.xport = xxi->nat_xport;
      axdat->nat_act.doct = 1;
      axdat->nat_act.rid = xf->pm.rule_id;
      axdat->nat_act.aid = xf->nm.sel_aid;
      axdat->nat_act.nv6 = key.v6 ? 1:0;
      axdat->nat_act.dsr = xf->nm.dsr;
      axdat->nat_act.cdis = xf->nm.cdis;
      axdat->nat_act.nmh = xf->nm.npmhh;
      axdat->ito = xf->nm.ito;
    } else {
      axdat->ito = 0;
      axdat->ca.act_type = DP_SET_DO_CT;
    }
    axdat->lts = adat->lts;
    axdat->ctd.dir = CT_DIR_OUT;
    axdat->ctd.smr = CT_SMR_INIT;
    axdat->ctd.rid = adat->ctd.rid;
    axdat->ctd.aid = adat->ctd.aid;
    axdat->ctd.nid = adat->ctd.nid;
    axdat->ctd.pi.npmhh = xf->nm.npmhh;
    axdat->ctd.pi.pmhh[0] = xf->nm.pmhh[0];
    axdat->ctd.pi.pmhh[1] = xf->nm.pmhh[1];
    axdat->ctd.pi.pmhh[2] = xf->nm.pmhh[2]; // LLB_MAX_MHOSTS
    axdat->ctd.pb.bytes = 0;
    axdat->ctd.pb.packets = 0;

    bpf_map_update_elem(&ct_map, &xkey, axdat, BPF_ANY);
    bpf_map_update_elem(&ct_map, &key, adat, BPF_ANY);

    atdat = bpf_map_lookup_elem(&ct_map, &key);
    axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
  }

  if (atdat != NULL && axtdat != NULL) {
    atdat->lts = bpf_ktime_get_ns();
    axtdat->lts = atdat->lts;
    if (atdat->ctd.dir == CT_DIR_IN) {
      xf->pm.dir = CT_DIR_IN;
      LL_DBG_PRINTK("[CTRK] in-dir");
      xf->pm.phit |= LLB_DP_CTSI_HIT;
      smr = dp_ct_sm(ctx, xf, atdat, axtdat, CT_DIR_IN);
    } else {
      LL_DBG_PRINTK("[CTRK] out-dir");
      xf->pm.dir = CT_DIR_OUT;
      xf->pm.phit |= LLB_DP_CTSO_HIT;
      smr = dp_ct_sm(ctx, xf, axtdat, atdat, CT_DIR_OUT);
    }

    LL_DBG_PRINTK("[CTRK] smr %d", smr);

    if (smr == CT_SMR_EST) {
      if (xi->nat_flags) {
        atdat->nat_act.doct = 0;
        axtdat->nat_act.doct = 0;
        if (atdat->ctd.dir == CT_DIR_IN) {
          dp_ct_est(xf, &key, &xkey, atdat, axtdat);
        } else {
          dp_ct_est(xf, &xkey, &key, axtdat, atdat);
        }
        atdat->ctd.xi.mhon = 0;
        axtdat->ctd.xi.mhon = 0;
      } else {
        atdat->ca.act_type = DP_SET_NOP;
        axtdat->ca.act_type = DP_SET_NOP;
      }
    } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
      bpf_map_delete_elem(&ct_map, &xkey);
      bpf_map_delete_elem(&ct_map, &key);

      if (atdat->ctd.dir == CT_DIR_IN) {
        dp_ct_ctd(xf, &key, &xkey, atdat, axtdat);
      } else {
        dp_ct_ctd(xf, &xkey, &key, axtdat, atdat);
      }

      if (xi->nat_flags) {
        dp_do_dec_nat_sess(ctx, xf, atdat->ctd.rid, atdat->ctd.aid);
      }
    }
  }

  return smr; 
}
