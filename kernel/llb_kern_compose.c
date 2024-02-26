/*
 *  llb_kern_composer.c: LoxiLB Kernel eBPF packet composer/decomposer
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

static int __always_inline
dp_parse_eth(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct ethhdr *eth;
  eth = DP_TC_PTR(p->dbegin);

  if (eth + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (p->inp) {
    xf->il2m.valid = 1;
    memcpy(xf->il2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->il2m.dl_type = eth->h_proto;
  } else {
    xf->l2m.valid = 1;
    memcpy(xf->l2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->l2m.dl_type = eth->h_proto;
  }

  if (!ETH_TYPE_ETH2(eth->h_proto)) {
    return DP_PRET_PASS;
  }

  p->dbegin = DP_ADD_PTR(eth, sizeof(*eth));

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_vlan(struct parser *p,
              void *md,
              struct xfi *xf)
{
#ifndef LL_TC_EBPF
  struct vlanhdr *vlh;
  int vlan_depth;
  vlh = DP_TC_PTR(p->dbegin);
#endif

#ifndef LL_TC_EBPF
#pragma unroll
  for (vlan_depth = 0; vlan_depth < MAX_STACKED_VLANS; vlan_depth++) {
    if (!proto_is_vlan(xf->l2m.dl_type))
      break;

    if (vlh + 1 > p->dend) {
      return DP_PRET_FAIL;
    }

    xf->l2m.dl_type = vlh->h_vlan_encapsulated_proto;
    xf->l2m.vlan[vlan_depth] = vlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
    vlh++;
  }
  p->dbegin = DP_TC_PTR(vlh);
#else
  dp_vlan_info(xf, md); 
#endif

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_vlan_d1(struct parser *p,
               void *md,
               struct xfi *xf)
{
  struct vlanhdr *vlh;

  vlh = DP_TC_PTR(p->dbegin);

  /* Only one inner vlan is supported */
  if (proto_is_vlan(xf->il2m.dl_type)) {

    if (vlh + 1 > p->dend) {
      return DP_PRET_FAIL;
    }

    xf->il2m.dl_type = vlh->h_vlan_encapsulated_proto;
    xf->il2m.vlan[0] = vlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
    vlh++;
    p->dbegin = DP_TC_PTR(vlh);
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_arp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct arp_ethhdr *arp = DP_TC_PTR(p->dbegin);

  if (arp + 1 > p->dend) {
      return DP_PRET_FAIL;
  }

  if (p->inp) {
    if (arp->ar_pro == bpf_htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->il34m.saddr4 = arp->ar_spa;
      xf->il34m.daddr4 = arp->ar_tpa;
    }
    xf->il34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
  } else {
    if (arp->ar_pro == bpf_htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->l34m.saddr4 = arp->ar_spa;
      xf->l34m.daddr4 = arp->ar_tpa;
    }
    xf->l34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
  }

  return DP_PRET_TRAP;
}

static int __always_inline
dp_parse_tcp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct tcphdr *tcp = DP_TC_PTR(p->dbegin);
  __u8 tcp_flags = 0;

  if (tcp + 1 > p->dend) {
    /* In case of fragmented packets */
    return DP_PRET_OK;
  }

  if (tcp->fin)
    tcp_flags = LLB_TCP_FIN;
  if (tcp->rst)
    tcp_flags |= LLB_TCP_RST;
  if (tcp->syn)
    tcp_flags |= LLB_TCP_SYN;
  if (tcp->psh)
    tcp_flags |= LLB_TCP_PSH;
  if (tcp->ack)
    tcp_flags |= LLB_TCP_ACK;
  if (tcp->urg)
    tcp_flags |= LLB_TCP_URG;

  if (p->inp) {
    if (tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
      xf->pm.il4fin = 1;
    }

    xf->il34m.source = tcp->source;
    xf->il34m.dest = tcp->dest;
    xf->il34m.seq = tcp->seq;
    xf->pm.itcp_flags = tcp_flags;
  } else {
    if (tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
      xf->pm.l4fin = 1;
    }

    xf->l34m.source = tcp->source;
    xf->l34m.dest = tcp->dest;
    xf->l34m.seq = tcp->seq;
    xf->pm.tcp_flags = tcp_flags;
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_icmp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct icmphdr *icmp = DP_TC_PTR(p->dbegin);

  if (icmp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp->type == ICMP_ECHOREPLY ||
    icmp->type == ICMP_ECHO)) {
    if (p->inp) {
      xf->il34m.source = icmp->un.echo.id;
      xf->il34m.dest = icmp->un.echo.id;
    } else {
      xf->l34m.source = icmp->un.echo.id;
      xf->l34m.dest = icmp->un.echo.id;
    }
  }
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_iudp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct udphdr *udp = DP_TC_PTR(p->dbegin);
  
  if (udp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  xf->il34m.source = udp->source;
  xf->il34m.dest = udp->dest;

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_sctp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct sctp_dch *c;
  struct sctphdr *sctp = DP_TC_PTR(p->dbegin);

  if (sctp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if (p->inp) {
    xf->il34m.source = sctp->source;
    xf->il34m.dest = sctp->dest;
  } else {
    xf->l34m.source = sctp->source;
    xf->l34m.dest = sctp->dest;
  }

  c = DP_TC_PTR(DP_ADD_PTR(sctp, sizeof(*sctp)));

  /* Chunks need not be present in all sctp packets */
  if (c + 1 > p->dend) {
    return DP_PRET_OK;
  }

  /* Parsing only one-level of chunk */
  if (c->type == SCTP_ERROR ||
    c->type == SCTP_ABORT ||
    c->type == SCTP_SHUT  ||
    c->type == SCTP_SHUT_ACK ||
    c->type == SCTP_SHUT_COMPLETE) {
    if (p->inp) {
      xf->pm.il4fin = 1;
    } else {
      xf->pm.l4fin = 1;
    }
  } else if (c->type == SCTP_HB_REQ ||
             c->type == SCTP_HB_ACK ||
             c->type == SCTP_INIT_CHUNK ||
             c->type == SCTP_INIT_CHUNK_ACK) {
    xf->pm.goct = 1;
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_icmp6(struct parser *p,
               void *md,
               struct xfi *xf)
{
  struct icmp6hdr *icmp6 = DP_TC_PTR(p->dbegin);

  if (icmp6 + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
      icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
    if (p->inp) {
      xf->il34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->il34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    } else {
      xf->l34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->l34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    }
  } else if (icmp6->icmp6_type >= 133 &&
            icmp6->icmp6_type <= 137) {
    return DP_PRET_PASS;
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_ipv4_d1(struct parser *p,
                 void *md,
                 struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(p->dbegin);
  int iphl = iph->ihl << 2;

  if (iph + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (DP_ADD_PTR(iph, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  xf->pm.il3_len = bpf_ntohs(iph->tot_len);
  xf->pm.il3_plen = xf->pm.il3_len - iphl;

  xf->il34m.valid = 1;
  xf->il34m.tos = iph->tos & 0xfc;
  xf->il34m.nw_proto = iph->protocol;
  xf->il34m.saddr4 = iph->saddr;
  xf->il34m.daddr4 = iph->daddr;

  if (ip_is_first_fragment(iph)) {
    xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), p->start);
    p->dbegin = DP_ADD_PTR(iph, iphl);

    if (xf->il34m.nw_proto == IPPROTO_TCP) {
      return dp_parse_tcp(p, md, xf);
    } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
      return dp_parse_iudp(p, md, xf);
    } else if (xf->il34m.nw_proto == IPPROTO_SCTP) {
      return dp_parse_sctp(p, md, xf);
    } else if (xf->il34m.nw_proto == IPPROTO_ICMP) {
      return dp_parse_icmp(p, md, xf);
    } else if (xf->il34m.nw_proto == IPPROTO_ESP ||
             xf->il34m.nw_proto == IPPROTO_AH) {
      /* Let xfrm handle it */
      return DP_PRET_PASS;
    }
  } else {
    if (ip_is_fragment(iph)) {
      xf->il34m.source = iph->id;
      xf->il34m.dest = iph->id;
      xf->il34m.frg = 1;
    }
  }
  
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_ipv6_d1(struct parser *p,
                 void *md,
                 struct xfi *xf)
{
  struct ipv6hdr *ip6 = DP_TC_PTR(p->dbegin);

  if (ip6 + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ipv6_addr_is_multicast(&ip6->daddr) ||
      ipv6_addr_is_multicast(&ip6->saddr)) {
    return DP_PRET_PASS;
  }

  xf->pm.il3_plen = bpf_ntohs(ip6->payload_len);
  xf->pm.il3_len =  xf->pm.il3_plen + sizeof(*ip6);

  xf->il34m.valid = 1;
  xf->il34m.tos = ((ip6->priority << 4) |
               ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
  xf->il34m.nw_proto = ip6->nexthdr;
  memcpy(&xf->il34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
  memcpy(&xf->il34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

  xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), p->start);
  p->dbegin = DP_ADD_PTR(ip6, sizeof(*ip6));

  if (xf->il34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_iudp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
    return dp_parse_icmp6(p, md, xf);
  }
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_d1(struct parser *p,
            void *md,
            struct xfi *xf)
{
  int ret = 0;

  if (p->skip_l2) {
    if (xf->il2m.dl_type == 0)
      return DP_PRET_TRAP;
    goto proc_inl3;
  }

  if ((ret = dp_parse_eth(p, md, xf))) {
    return ret;
  }

  if ((ret = dp_parse_vlan_d1(p, md, xf))) {
    return ret;
  }

proc_inl3:
  xf->pm.il3_off = DP_DIFF_PTR(p->dbegin, p->start);

  if (xf->il2m.dl_type == bpf_htons(ETH_P_ARP)) {
    ret = dp_parse_arp(p, md, xf);
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IP)) {
    ret = dp_parse_ipv4_d1(p, md, xf);
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (p->skip_v6 == 0)
      ret = dp_parse_ipv6_d1(p, md, xf);
  }

  return ret;
} 

static int __always_inline
dp_parse_gtp_ehdr(void *nh, void *dend)
{
  uint8_t *nhl = DP_TC_PTR(nh);
  uint8_t *neh;
  int elen;

  if (nhl + 1 > dend) {
    return DP_PRET_FAIL;
  }

  elen = *nhl<<2;

  if (nhl + elen > dend) {
    return DP_PRET_FAIL;
  }

  neh = nhl + (elen - 1);

  if (*neh) return elen;

  return DP_PRET_OK;
}

#ifdef HAVE_LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") gparser = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct gtp_parser),
  .max_entries = 1,
};
#else
struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct gtp_parser);
        __uint(max_entries, 1);
} gparser SEC(".maps");
#endif

static int __always_inline
dp_parse_gtp(struct parser *p,
             void *md,
             void *inp,
             struct xfi *xf)
{
  int var = 0;
  struct gtp_parser *gp;

  gp = bpf_map_lookup_elem(&gparser, &var);
  if (!gp) {
    goto drop;
  }

  gp->hlen = GTP_HDR_LEN;
  gp->gh = DP_TC_PTR(inp);

  if (gp->gh + 1 > p->dend) {
    goto drop;
  }

  if (gp->gh->ver != GTP_VER_1) {
    return DP_PRET_OK;
  }

  if (gp->gh->espn) gp->hlen += sizeof(struct gtp_v1_ehdr);

  xf->tm.tunnel_id = bpf_ntohl(gp->gh->teid);
  xf->tm.tun_type = LLB_TUN_GTP;

  if (gp->gh->espn & GTP_EXT_FM) {
    gp->geh = DP_ADD_PTR(gp->gh, sizeof(struct gtp_v1_hdr));

    if (gp->geh + 1 > p->dend) {
      goto drop;
    }

    gp->nh = DP_ADD_PTR(gp->geh, sizeof(struct gtp_v1_ehdr));

    /* PDU session container is always first */
    if (gp->geh->next_hdr == GTP_NH_PDU_SESS) {
      struct gtp_pdu_sess_cmnhdr *pch = DP_TC_PTR(gp->nh);

      if (pch + 1 > p->dend) {
        goto drop;
      }

      if (pch->len != 1) {
        goto drop;
      }

      if (pch->pdu_type == GTP_PDU_SESS_UL) {
        struct gtp_ul_pdu_sess_hdr *pul = DP_TC_PTR(pch);

        if (pul + 1 > p->dend) {
          goto drop;
        }

        gp->hlen += sizeof(*pul);
        xf->qm.qfi = pul->qfi;
        gp->nh = pul+1;

        if (pul->next_hdr == 0) goto done;

      } else if (pch->pdu_type == GTP_PDU_SESS_DL) {
        struct gtp_dl_pdu_sess_hdr *pdl = DP_TC_PTR(pch);

        if (pdl + 1 > p->dend) {
          goto drop;
        }

        gp->hlen += sizeof(*pdl);
        xf->qm.qfi = pdl->qfi;
        gp->nh = pdl+1;

        if (pdl->next_hdr == 0) goto done;

      } else {
        goto drop;
      }
    }

    gp->nhl = DP_TC_PTR(gp->nh);

    /* Parse maximum GTP_MAX_EXTH  gtp extension headers */
    for (var = 0; var < GTP_MAX_EXTH; var++) {

      if (gp->nhl + 1 > p->dend) {
        goto drop;
      }

      gp->elen = *(gp->nhl)<<2;

      gp->neh = gp->nhl + (gp->elen - 1);
      if (gp->neh + 1 > p->dend) {
        goto drop;
      }

      gp->hlen += gp->elen;
      if (*(gp->neh) == 0) break;
      gp->nhl = DP_ADD_PTR(gp->nhl, gp->elen);
    }

    if (var >= GTP_MAX_EXTH) {
      goto pass;
    }
  }

done:
  gp->gtp_next = DP_ADD_PTR(gp->gh, gp->hlen);
  xf->pm.tun_off = DP_DIFF_PTR(gp->gtp_next, DP_PDATA(md));

  gp->neh = DP_TC_PTR(gp->gtp_next);
  if (gp->neh + 1 > p->dend) {
    return 0;
  }

  var = ((*(gp->neh) & 0xf0) >> 4);

  if (var == 4) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IP);
  } else if (var == 6) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IPV6);
  } else {
    return DP_PRET_OK;
  }

  p->inp = 1;
  p->skip_l2 = 1;
  p->dbegin = gp->gtp_next;
  return dp_parse_d1(p, md, xf);

drop:
  return DP_PRET_FAIL;

pass:
  return DP_PRET_PASS;
}

static int __always_inline
dp_parse_outer_udp(struct parser *p,
                   void *md,
                   void *udp_next,
                   struct xfi *xf)
{
  struct vxlanhdr *vx;
  struct gtp_v1_hdr *gh; 
  void *dend = DP_TC_PTR(DP_PDATA_END(md)); 
  void *vx_next;

  switch (xf->l34m.dest) {
  case bpf_htons(VXLAN_OUDP_DPORT) :
    vx = DP_TC_PTR(udp_next);
    if (vx + 1 > dend) {
      return DP_PRET_FAIL;
    }

    xf->tm.tunnel_id = (bpf_ntohl(vx->vx_vni)) >> 8 & 0xfffffff;
    xf->tm.tun_type = LLB_TUN_VXLAN;
    vx_next = vx + 1;
    xf->pm.tun_off = DP_DIFF_PTR(vx_next, DP_PDATA(md));

    LL_DBG_PRINTK("[PRSR] UDP VXLAN %u\n", xf->tm.tunnel_id);
    p->inp = 1;
    p->skip_l2 = 0;
    p->dbegin = vx_next;
    return dp_parse_d1(p, md, xf);
    break;
  case bpf_htons(GTPU_UDP_DPORT):
  case bpf_htons(GTPC_UDP_DPORT):
    gh = DP_TC_PTR(udp_next);
    if (gh + 1 > dend) {
      return DP_PRET_FAIL;
    }

    return dp_parse_gtp(p, md, gh, xf);
    break;
  default:
    return DP_PRET_OK;
  }

  /* Not reached */
  return 0;
} 

static int __always_inline
dp_parse_llb(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct ethhdr *eth;
  struct llb_ethhdr *llb = DP_TC_PTR(p->dbegin);

  LL_DBG_PRINTK("[PRSR] LLB \n");

#ifdef LL_TC_EBPF
  return DP_PRET_FAIL;
#endif

  if (DP_TC_PTR(p->dbegin) + (sizeof(struct ethhdr) + sizeof(*llb)) > p->dend) {
    return DP_PRET_FAIL;
  }

  llb = DP_ADD_PTR(p->dbegin, sizeof(struct ethhdr));
  xf->pm.oport = (llb->oport);
  xf->pm.iport = (llb->iport);

  eth = DP_ADD_PTR(p->dbegin, (int)sizeof(struct llb_ethhdr));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = llb->ntype;

  if (dp_remove_l2(md, (int)sizeof(*llb))) {
    return DP_PRET_FAIL;
  }

#ifndef LL_TC_EBPF
  if (1) {
    struct ll_xmdi *xm;
    if (bpf_xdp_adjust_meta(md, -(int)sizeof(*xm)) < 0) {
      LL_DBG_PRINTK("[PRSR] adjust meta fail\n");
      return DP_PRET_FAIL;
    }

    p->dbegin = DP_TC_PTR(DP_PDATA(md));
    xm = DP_TC_PTR(DP_MDATA(md));
    if (xm + 1 >  p->dbegin) {
      return DP_PRET_FAIL;
    }

    xm->pi.oport = xf->pm.oport;
    xm->pi.iport = xf->pm.iport;
    xm->pi.skip = 0;
  }
#endif
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_udp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct udphdr *udp = DP_TC_PTR(p->dbegin);
  
  if (udp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;

  if (dp_pkt_is_l2mcbc(xf, md) == 1) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_BCMC);
  }

  return dp_parse_outer_udp(p, md, udp + 1, xf);
}

static int __always_inline
dp_parse_ipip(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct iphdr *ip = DP_TC_PTR(p->dbegin);
  int iphl = ip->ihl << 2;
  
  if (ip + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if (DP_ADD_PTR(ip, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ip->version == 4) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IP);
  } else {
    return DP_PRET_OK;
  }

  xf->tm.tunnel_id = 1; // No real use
  xf->tm.tun_type = LLB_TUN_IPIP;

  p->inp = 1;
  p->skip_l2 = 1;
  p->dbegin = ip;
  return dp_parse_d1(p, md, xf);
}

static int __always_inline
dp_parse_ipv4(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(p->dbegin);
  int iphl = iph->ihl << 2;

  if (iph + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (DP_ADD_PTR(iph, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  xf->pm.l3_len = bpf_ntohs(iph->tot_len);
  xf->pm.l3_plen = xf->pm.l3_len - iphl;

  xf->l34m.valid = 1;
  xf->l34m.tos = iph->tos & 0xfc;
  xf->l34m.nw_proto = iph->protocol;
  xf->l34m.saddr4 = iph->saddr;
  xf->l34m.daddr4 = iph->daddr;

  if (ip_is_first_fragment(iph)) {
    xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), p->start);
    p->dbegin = DP_ADD_PTR(iph, iphl);

    if (ip_is_fragment(iph)) {
      xf->l2m.ssnid = iph->id;
      xf->pm.goct = 1;
    }

    if (xf->l34m.nw_proto == IPPROTO_TCP) {
      return dp_parse_tcp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
      return dp_parse_udp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_SCTP) {
      return dp_parse_sctp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_ICMP) {
      return dp_parse_icmp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_IPIP) {
      return dp_parse_ipip(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_ESP ||
             xf->l34m.nw_proto == IPPROTO_AH) {
    /* Let xfrm handle it */
      return DP_PRET_PASS;
    }
  } else {
    if (ip_is_fragment(iph)) {
      xf->l34m.source = iph->id;
      xf->l34m.dest = iph->id;
      xf->l2m.ssnid = iph->id;
      xf->l34m.frg = 1;
    }
  }
  
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_ipv6(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct ipv6hdr *ip6 = DP_TC_PTR(p->dbegin);

  if (ip6 + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ipv6_addr_is_multicast(&ip6->daddr) ||
      ipv6_addr_is_multicast(&ip6->saddr)) {
    return DP_PRET_PASS;
  }

  xf->pm.l3_plen = bpf_ntohs(ip6->payload_len);
  xf->pm.l3_len =  xf->pm.l3_plen + sizeof(*ip6);

  xf->l34m.valid = 1;
  xf->l34m.tos = ((ip6->priority << 4) |
               ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
  xf->l34m.nw_proto = ip6->nexthdr;
  memcpy(&xf->l34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
  memcpy(&xf->l34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

  xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), p->start);
  p->dbegin = DP_ADD_PTR(ip6, sizeof(*ip6));

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_udp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP) {
    return dp_parse_sctp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
    return dp_parse_icmp6(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ESP ||
             xf->l34m.nw_proto == IPPROTO_AH) {
    /* Let xfrm handle it */
    return DP_PRET_PASS;
  }
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_d0(void *md,
            struct xfi *xf,
            int skip_v6)
{
  int ret = 0;
  struct parser p;

  p.inp = 0;
  p.skip_l2 = 0;
  p.skip_v6 = skip_v6;
  p.start = DP_TC_PTR(DP_PDATA(md));
  p.dbegin = DP_TC_PTR(p.start);
  p.dend = DP_TC_PTR(DP_PDATA_END(md));
  xf->pm.py_bytes = DP_DIFF_PTR(p.dend, p.dbegin);

  if ((ret = dp_parse_eth(&p, md, xf))) {
    goto handle_excp;
  }

  if (DP_NEED_MIRR(md)) {
    xf->pm.mirr = DP_GET_MIRR(md);
    LL_DBG_PRINTK("[PRSR] LB %d %d\n", xf->pm.mirr, DP_IFI(md));
  }

#ifdef HAVE_DP_IPC
  if (xdp2tc_has_xmd(md, xf)) {
    return 1;
  }
#endif

  if ((ret = dp_parse_vlan(&p, md, xf))) {
    goto handle_excp;
  }

  xf->pm.l3_off = DP_DIFF_PTR(p.dbegin, p.start);

  if (xf->l2m.dl_type == bpf_htons(ETH_P_ARP)) {
    ret = dp_parse_arp(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    ret = dp_parse_ipv4(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (p.skip_v6 == 1) {
      return 0;
    }
    ret = dp_parse_ipv6(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_TYPE_LLB)) {
    ret = dp_parse_llb(&p, md, xf);
  }

  if (ret != 0) {
    goto handle_excp;
  }

  if (dp_pkt_is_l2mcbc(xf, md) == 1) {
    LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_BCMC);
  }

  return 0;

handle_excp:
  if (ret > DP_PRET_OK) {
    //if (ret == DP_PRET_PASS) {
      LLBS_PPLN_PASSC(xf, LLB_PIPE_RC_PARSER);
    //} else {
    //  LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_PARSER);
    //}
  } else if (ret < DP_PRET_OK) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PARSER);
  }
  return ret;
}

static int __always_inline
dp_unparse_packet_always_slow(void *ctx,  struct xfi *xf)
{
  xf->pm.phit |= LLB_DP_UNPS_HIT;

  if (xf->pm.nf & LLB_NAT_SRC) {
    LL_DBG_PRINTK("[DEPR] LL_SNAT 0x%lx:%x\n", xf->nm.nxip4, xf->nm.nxport);
    /* If packet is v6 */
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
        if (xf->nm.nv6) {
          if (dp_do_snat6(ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {
             return DP_DROP;
          }
        } else {
          /* TODO */
          return DP_DROP;
        }
    } else { /* If packet is v4 */

      if (xf->nm.nv6 == 0) {
        if (dp_do_snat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
        if (dp_do_snat46(ctx, xf) != 0) {
          return DP_DROP;
        }
        if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {
          xf->pm.oport = xf->pm.iport;
          return dp_rewire_port(&tx_intf_map, xf);
        }
      }
    }
  } else if (xf->pm.nf & LLB_NAT_DST) {
    LL_DBG_PRINTK("[DEPR] LL_DNAT 0x%x\n", xf->nm.nxip4, xf->nm.nxport);

    /* If packet is v6 */
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
      if (xf->nm.nv6 == 1) {
        if (dp_do_dnat6(ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
        if (dp_do_dnat64(ctx, xf)) {
          return DP_DROP;
        }
      }
    } else { /* If packet is v4 */
      if (xf->nm.nv6 == 0) {
        if (dp_do_dnat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
          /* TODO */
          return DP_DROP;
      }
    }
  }

  xf->pm.nf = 0;

  RETURN_TO_MP_OUT();

  return DP_DROP;
}

static int __always_inline
dp_unparse_packet_always(void *ctx,  struct xfi *xf)
{

  if (xf->pm.nf & LLB_NAT_SRC && xf->nm.dsr == 0) {
    LL_DBG_PRINTK("[DEPR] LL_SNAT 0x%lx:%x\n",
                 xf->nm.nxip4, xf->nm.nxport);
    if (xf->pm.rcode & (LLB_PIPE_RC_NODMAC|LLB_PIPE_RC_NH_UNK|LLB_PIPE_RC_RT_TRAP)) {
      xf->pm.pten = DP_PTEN_ALL;
      xf->pm.rcode |= LLB_PIPE_RC_RESOLVE;
      dp_ring_event(ctx, xf, 1);
    }
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) || xf->nm.nv6) {
      dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_snat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->pm.nf & LLB_NAT_DST && xf->nm.dsr == 0) {
    LL_DBG_PRINTK("[DEPR] LL_DNAT 0x%x\n",
                  xf->nm.nxip4, xf->nm.nxport);
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
      dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_dnat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
        return DP_DROP;
      }
    }
  }

  if (xf->tm.tun_decap) {
    if (xf->tm.tun_type == LLB_TUN_GTP) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-GTP\n");
      if (dp_do_strip_gtp(ctx, xf, xf->pm.tun_off) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->tm.new_tunnel_id) {
    if (xf->tm.tun_type == LLB_TUN_GTP) {
      if (dp_do_ins_gtp(ctx, xf,
                        xf->tm.tun_rip,
                        xf->tm.tun_sip,
                        xf->tm.new_tunnel_id,
                        xf->qm.qfi,
                        1)) {
        return DP_DROP;
      }
    }
  }

  return 0;
}

static int __always_inline
dp_unparse_packet(void *ctx,  struct xfi *xf)
{
  if (xf->tm.tun_decap) {
    if (xf->tm.tun_type == LLB_TUN_VXLAN) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-VXLAN\n");
      if (dp_do_strip_vxlan(ctx, xf, xf->pm.tun_off) != 0) {
        return DP_DROP;
      }
    } else if (xf->tm.tun_type == LLB_TUN_IPIP) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-IPIP\n");
      if (dp_do_strip_ipip(ctx, xf) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->tm.new_tunnel_id) {
    LL_DBG_PRINTK("[DEPR] LL_NEW-TUN 0x%x\n",
                  bpf_ntohl(xf->tm.new_tunnel_id));
    if (xf->tm.tun_type == LLB_TUN_VXLAN) {
      if (dp_do_ins_vxlan(ctx, xf,
                          xf->tm.tun_rip,
                          xf->tm.tun_sip,
                          xf->tm.new_tunnel_id,
                          1)) {
        return DP_DROP;
      }
    } else if (xf->tm.tun_type == LLB_TUN_IPIP) {
      LL_DBG_PRINTK("[DEPR] LL_NEW-IPTUN 0x%x\n",
                  bpf_ntohl(xf->tm.new_tunnel_id));
      if (dp_do_ins_ipip(ctx, xf,
                         xf->tm.tun_rip,
                         xf->tm.tun_sip,
                         xf->tm.new_tunnel_id,
                         1)) {
        return DP_DROP;
      }
    }
  }

  return dp_do_out_vlan(ctx, xf);
}
