/*
 *  llb_kern_composer.c: LoxiLB Kernel eBPF packet composer/decomposer
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

static int __always_inline
dp_parse_inner_packet(void *md,
                      void *inp,
                      int  skip_l2,
                      struct xfi *xf)
{
  struct vlan_hdr *ivlh;
  struct ethhdr *ieth;
  void *dend = DP_TC_PTR(DP_PDATA_END(md)); 

  if (skip_l2) {
    ivlh = DP_TC_PTR(inp);

    if (xf->il2m.dl_type == 0)
      return 1;

    goto proc_inl3;
  }

  ieth = DP_TC_PTR(inp);

  if (ieth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->il2m.valid = 1;
  memcpy(xf->il2m.dl_dst, ieth->h_dest, 2*6);
  xf->il2m.dl_type = ieth->h_proto;

  /* 802.2 */
  if (ieth->h_proto < bpf_htons(1536)) {
    return XDP_PASS;
  }

  /* Only one inner vlan is supported */
  ivlh = DP_ADD_PTR(ieth, sizeof(*ieth));
  if (proto_is_vlan(ieth->h_proto)) {

    if (ivlh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->il2m.dl_type = ivlh->h_vlan_encapsulated_proto;
    xf->il2m.vlan[0] = ivlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
  }

proc_inl3:
  if (xf->il2m.dl_type == bpf_htons(ETH_P_ARP)) {
    struct arp_ethheader *arp = DP_TC_PTR(ivlh);

    if (arp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (arp->ar_pro == bpf_htons(ETH_P_IP) &&
        arp->ar_pln == 4) {
      xf->il34m.saddr4 = arp->ar_spa;
      xf->l34m.daddr4 = arp->ar_tpa;
    }
    xf->il34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
    return 1;
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = DP_TC_PTR(ivlh);
    int iphl = iph->ihl << 2;

    if (iph + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_ADD_PTR(iph, iphl) > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->pm.il3_len = bpf_ntohs(iph->tot_len);
    xf->pm.il3_plen = xf->pm.il3_len - iphl;
    xf->pm.il3_off = DP_DIFF_PTR(iph, DP_PDATA(md));

    xf->il34m.valid = 1;
    xf->il34m.tos = iph->tos & 0xfc;
    xf->il34m.nw_proto = iph->protocol;
    xf->il34m.saddr4 = iph->saddr;
    xf->il34m.daddr4 = iph->daddr;

    if (!ip_is_fragment(iph)) {

      xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), DP_PDATA(md));

      if (xf->il34m.nw_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = DP_ADD_PTR(iph, iphl);

        if (tcp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return -1;
        }

        if (tcp->fin)
          xf->pm.itcp_flags = LLB_TCP_FIN;
        if (tcp->rst)
          xf->pm.itcp_flags |= LLB_TCP_RST;
        if (tcp->syn)
          xf->pm.itcp_flags |= LLB_TCP_SYN;
        if (tcp->psh)
          xf->pm.itcp_flags |= LLB_TCP_PSH;
        if (tcp->ack)
          xf->pm.itcp_flags |= LLB_TCP_ACK;
        if (tcp->urg)
          xf->pm.itcp_flags |= LLB_TCP_URG;

        if (xf->pm.itcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
          xf->pm.il4fin = 1;
        }

        xf->il34m.source = tcp->source;
        xf->il34m.dest = tcp->dest;
        xf->il34m.seq = tcp->seq;
        xf->il34m.ack = tcp->ack_seq;
      } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
        struct udphdr *udp = DP_ADD_PTR(iph, iphl);

        if (udp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return -1;
        }

        xf->il34m.source = udp->source;
        xf->il34m.dest = udp->dest;
      } else if (xf->il34m.nw_proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = DP_ADD_PTR(iph, iphl);

        if (icmp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return -1;
        }

        if (icmp->type == ICMP_ECHOREPLY ||
            icmp->type == ICMP_ECHO) {
           xf->il34m.source = icmp->un.echo.id;
           xf->il34m.dest = icmp->un.echo.id;
        }
      } else if (xf->il34m.nw_proto == IPPROTO_SCTP) {
        struct sctp_dch *c;
        struct sctphdr *sctp = DP_ADD_PTR(iph, iphl);
        
        if (sctp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return -1;
        }
  
        xf->il34m.source = sctp->source;
        xf->il34m.dest = sctp->dest;

        c = DP_TC_PTR(DP_ADD_PTR(sctp, sizeof(*sctp)));
  
        /* Chunks need not be present in all sctp packets */
        if (c + 1 > dend) {
          return 0;
        }

        if (c->type == SCTP_ERROR ||
            c->type == SCTP_ABORT ||
            c->type == SCTP_SHUT  ||
            c->type == SCTP_SHUT_ACK ||
            c->type == SCTP_SHUT_COMPLETE) {
          xf->pm.il4fin = 1;
        } 

      }
    } else {
      /* Let Linux stack handle it */
      return XDP_PASS;
    }
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = DP_TC_PTR(ivlh);

    if (ip6 + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->pm.il3_plen = bpf_ntohs(ip6->payload_len);
    xf->pm.il3_len =  xf->pm.il3_plen + sizeof(*ip6);
    xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), DP_PDATA(md));

    xf->il34m.valid = 1;
    xf->il34m.tos = ((ip6->priority << 4) |
                 ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
    xf->il34m.nw_proto = ip6->nexthdr;
    memcpy(&xf->il34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
    memcpy(&xf->il34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

    if (xf->il34m.nw_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = DP_ADD_PTR(ip6, sizeof(*ip6));
      if (tcp + 1 > dend) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }

      xf->il34m.source = tcp->source;
      xf->il34m.dest = tcp->dest;
      xf->il34m.seq = tcp->seq;
      xf->il34m.ack = tcp->ack_seq;
    } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
      struct udphdr *udp = DP_ADD_PTR(ip6, sizeof(*ip6));

      if (udp + 1 > dend) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }

      xf->il34m.source = udp->source;
      xf->il34m.dest = udp->dest;
    }
  }

  return 0;
} 

static int __always_inline
dp_parse_gtp_ehdr(void *nh, void *dend)
{
  uint8_t *nhl = DP_TC_PTR(nh);
  uint8_t *neh;
  int elen;

  if (nhl + 1 > dend) {
    return -1;
  }

  elen = *nhl<<2;

  if (nhl + elen > dend) {
    return -1;
  }

  neh = nhl + (elen - 1);

  if (*neh) return elen;

  return 0;
}

static int __always_inline
dp_parse_gtp(void *md,
             void *inp,
             struct xfi *xf)
{
  struct gtp_v1_hdr *gh;
  struct gtp_v1_ehdr *geh;
  int hlen = GTP_HDR_LEN;
  void *nh;
  void *gtp_next;
  void *dend;
  uint8_t *nhl;
  uint8_t *neh;
  int elen;
  int depth;

  gh = DP_TC_PTR(inp);
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (gh + 1 > dend) {
    goto drop;
  }

  if (gh->ver != GTP_VER_1) {
    return 0;
  }

  if (gh->espn) hlen += sizeof(*geh);

  xf->tm.tunnel_id = bpf_ntohl(gh->teid);
  xf->tm.tun_type = LLB_TUN_GTP;

  if (gh->espn & GTP_EXT_FM) {
    geh = DP_ADD_PTR(gh, sizeof(*gh));

    if (geh + 1 > dend) {
      goto drop;
    }

    nh = DP_ADD_PTR(geh, sizeof(*geh));

    /* PDU session container is always first */
    if (geh->next_hdr == GTP_NH_PDU_SESS) {
      struct gtp_pdu_sess_cmn_hdr *pch = DP_TC_PTR(nh);

      if (pch + 1 > dend) {
        goto drop;
      }

      if (pch->len != 1) {
        goto drop;
      }

      if (pch->pdu_type == GTP_PDU_SESS_UL) {
        struct gtp_ul_pdu_sess_hdr *pul = DP_TC_PTR(pch);

        if (pul + 1 > dend) {
          goto drop;
        }

        hlen += sizeof(*pul);
        xf->qm.qfi = pul->qfi;
        nh = pul+1;

        if (pul->next_hdr == 0) goto done;

      } else if (pch->pdu_type == GTP_PDU_SESS_DL) {
        struct gtp_dl_pdu_sess_hdr *pdl = DP_TC_PTR(pch);

        if (pdl + 1 > dend) {
          goto drop;
        }

        hlen += sizeof(*pdl);
        xf->qm.qfi = pdl->qfi;
        nh = pdl+1;

        if (pdl->next_hdr == 0) goto done;

      } else {
        goto drop;
      }
    }

    nhl = DP_TC_PTR(nh);

    /* Parse maximum GTP_MAX_EXTH  gtp extension headers */
#pragma unroll
    for (depth = 0; depth < GTP_MAX_EXTH; depth++) {

      if (nhl + 1 > dend) {
        goto drop;
      }

      elen = *nhl<<2;

      neh = nhl + (elen - 1);
      if (neh + 1 > dend) {
        goto drop;
      }

      hlen += elen;
      if (*neh == 0) break;
      nhl = DP_ADD_PTR(nhl, elen);
    }

    if (depth >= GTP_MAX_EXTH) {
      goto pass;
    }
  }

done:
  gtp_next = DP_ADD_PTR(gh, hlen);
  xf->pm.tun_off = DP_DIFF_PTR(gtp_next, DP_PDATA(md));

  neh = DP_TC_PTR(gtp_next);
  if (neh + 1 > dend) {
    return 0;
  }

  __u8 nv = ((*neh & 0xf0) >> 4);

  if (nv == 4) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IP);
  } else if (nv == 6) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IPV6);
  } else {
    return 0;
  }

  dp_parse_inner_packet(md, gtp_next, 1, xf);

  return 0;

drop:
  LLBS_PPLN_DROP(xf);
  return -1;

pass:
  LLBS_PPLN_PASS(xf);
  return 0;
}

static int __always_inline
dp_parse_outer_udp(void *md,
                   void *udp_next,
                   struct xfi *xf)
{
  struct vxlan_hdr *vx;
  struct gtp_v1_hdr *gh; 
  void *dend = DP_TC_PTR(DP_PDATA_END(md)); 
  void *vx_next;

  switch (xf->l34m.dest) {
  case bpf_htons(VXLAN_UDP_DPORT) :
    vx = DP_TC_PTR(udp_next);
    if (vx + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->tm.tunnel_id = (bpf_ntohl(vx->vx_vni)) >> 8 & 0xfffffff;
    xf->tm.tun_type = LLB_TUN_VXLAN;
    vx_next = vx + 1;
    xf->pm.tun_off = DP_DIFF_PTR(vx_next, DP_PDATA(md));

    LL_DBG_PRINTK("[PRSR] UDP VXLAN %u\n", xf->tm.tunnel_id);
    dp_parse_inner_packet(md, vx_next, 0, xf);
    break;
  case bpf_htons(GTPU_UDP_DPORT):
  case bpf_htons(GTPC_UDP_DPORT):
    gh = DP_TC_PTR(udp_next);
    if (gh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    dp_parse_gtp(md, gh, xf);
    break;
  default:
    return 1;
  }

  /* Not reached */
  return 0;
} 

static int __always_inline
dp_parse_packet(void *md,
                struct xfi *xf,
                int skip_md)
{
#ifndef LL_TC_EBPF
  int i = 0;
#endif
  __u32 fm_data;
  __u32 fm_data_end;
  __u16 h_proto;
  struct ethhdr *eth;
  struct vlan_hdr *vlh;
  void *dend;

  fm_data = DP_PDATA(md);
  fm_data_end = DP_PDATA_END(md);
  xf->pm.py_bytes = DP_DIFF_PTR(fm_data_end, fm_data);

  dend = DP_TC_PTR(fm_data_end);
  eth =  DP_TC_PTR(fm_data);

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->l2m.valid = 1;
  memcpy(xf->l2m.dl_dst, eth->h_dest, 2*6);
  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
  xf->l2m.dl_type = eth->h_proto;

  /* 802.2 */
  if (eth->h_proto < bpf_htons(1536)) {
    LLBS_PPLN_TRAP(xf);
    return 1;
  }

  if (DP_NEED_MIRR(md)) {
    xf->pm.mirr = DP_GET_MIRR(md);
    LL_DBG_PRINTK("[PRSR] LB %d %d\n", xf->pm.mirr, DP_IFI(md));
  }

  h_proto = eth->h_proto;

  if (skip_md == 0) {
    if (xdp2tc_has_xmd(md, xf)) {
      return 1;
    }
  }

  vlh = DP_ADD_PTR(eth, sizeof(*eth));

#ifndef LL_TC_EBPF
#pragma unroll
  for (i = 0; i < MAX_STACKED_VLANS; i++) {
    if (!proto_is_vlan(h_proto))
      break;

    if (vlh + 1 > dend)
      break;

    h_proto = vlh->h_vlan_encapsulated_proto;

    xf->l2m.vlan[i] = vlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
    vlh++;
  }
#else
  dp_vlan_info(xf, md); 
#endif

  xf->pm.l3_off = DP_DIFF_PTR(vlh, eth);

  xf->l2m.dl_type = h_proto;
  if (xf->l2m.dl_type == bpf_htons(ETH_P_ARP)) {
    struct arp_ethheader *arp = DP_TC_PTR(vlh);

    if (arp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (arp->ar_pro == bpf_htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->l34m.saddr4 = arp->ar_spa;
      xf->l34m.daddr4 = arp->ar_tpa;
    }
    xf->l34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_PARSER);
    return 1;
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_MPLS_UC) ||
             xf->l2m.dl_type == bpf_htons(ETH_P_MPLS_MC)) {
    struct mpls_header *mpls = DP_TC_PTR(vlh);

    if (mpls + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->l2m.mpls_label = bpf_htonl(MPLS_HDR_GET_LABEL(mpls->mpls_tag));
    xf->l2m.mpls_tc = MPLS_HDR_GET_TC(mpls->mpls_tag);
    xf->l2m.mpls_tc = MPLS_HDR_GET_BOS(mpls->mpls_tag);

  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    struct iphdr *iph = DP_TC_PTR(vlh);
    int iphl = iph->ihl << 2;

    if (iph + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_ADD_PTR(iph, iphl) > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    xf->pm.l3_len = bpf_ntohs(iph->tot_len);
    xf->pm.l3_plen = xf->pm.l3_len - iphl;

    xf->l34m.valid = 1;
    xf->l34m.tos = iph->tos & 0xfc;
    xf->l34m.nw_proto = iph->protocol;
    xf->l34m.saddr4 = iph->saddr;
    xf->l34m.daddr4 = iph->daddr;

    /* Earlier we used to have the following check here :
     * !ip_is_fragment(iph) || ip_is_first_fragment(iph))
     * But it seems to be unncessary as proper bound checking
     * is already taken care by eBPF verifier
     */
    if (1) {

      xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), eth);

      if (xf->l34m.nw_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = DP_ADD_PTR(iph, iphl);

        if (tcp + 1 > dend) {
          /* In case of fragmented packets */
          return 0;
        }

        if (tcp->fin)
          xf->pm.tcp_flags = LLB_TCP_FIN;
        if (tcp->rst)
          xf->pm.tcp_flags |= LLB_TCP_RST;
        if (tcp->syn)
          xf->pm.tcp_flags |= LLB_TCP_SYN;
        if (tcp->psh)
          xf->pm.tcp_flags |= LLB_TCP_PSH;
        if (tcp->ack)
          xf->pm.tcp_flags |= LLB_TCP_ACK;
        if (tcp->urg)
          xf->pm.tcp_flags |= LLB_TCP_URG;

        if (xf->pm.tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
          xf->pm.l4fin = 1;
        }

        xf->l34m.source = tcp->source;
        xf->l34m.dest = tcp->dest;
        xf->l34m.seq = tcp->seq;
        xf->l34m.ack = tcp->ack_seq;
      } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
        struct udphdr *udp = DP_ADD_PTR(iph, iphl);

        if (udp + 1 > dend) {
          return 0;
        }

        xf->l34m.source = udp->source;
        xf->l34m.dest = udp->dest;

        if (dp_pkt_is_l2mcbc(xf, md) == 1) {
          LLBS_PPLN_TRAP(xf);
        }

        return dp_parse_outer_udp(md, udp + 1, xf);
      } else if (xf->l34m.nw_proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = DP_ADD_PTR(iph, iphl);

        if (icmp + 1 > dend) {
          return 0;
        }

        if ((icmp->type == ICMP_ECHOREPLY ||
            icmp->type == ICMP_ECHO)) {
           xf->l34m.source = icmp->un.echo.id;
           xf->l34m.dest = icmp->un.echo.id;
        } 
      } else if (xf->l34m.nw_proto == IPPROTO_SCTP) {
        struct sctp_dch *c;
        struct sctphdr *sctp = DP_ADD_PTR(iph, iphl);

        if (sctp + 1 > dend) {
          return 0;
        }

        xf->l34m.source = sctp->source;
        xf->l34m.dest = sctp->dest;
  
        c = DP_TC_PTR(DP_ADD_PTR(sctp, sizeof(*sctp)));

        /* Chunks need not be present in all sctp packets */
        if (c + 1 > dend) {
          return 0;
        }

        /* Parsing only one-level of chunk */
        if (c->type == SCTP_ERROR ||
            c->type == SCTP_ABORT ||
            c->type == SCTP_SHUT  ||
            c->type == SCTP_SHUT_ACK ||
            c->type == SCTP_SHUT_COMPLETE) {
          xf->pm.l4fin = 1;
        }
      } else if (xf->l34m.nw_proto == IPPROTO_ESP ||
                 xf->l34m.nw_proto == IPPROTO_AH) {
        /* Let xfrm handle it */
        LLBS_PPLN_PASS(xf);
        return 1;
      }

      if (ip_is_fragment(iph)) {
         xf->l34m.source = 0;
         xf->l34m.dest = 0;
      }
    } else {
#ifndef LL_HANDLE_NO_FRAG
      return 0;
#else
      /* Let Linux stack handle it */
      LLBS_PPLN_PASS(xf);
      return 1;
#endif
    }
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    struct ipv6hdr *ip6 = DP_TC_PTR(vlh);

    if (ip6 + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (ipv6_addr_is_multicast(&ip6->daddr) ||
        ipv6_addr_is_multicast(&ip6->saddr)) {
      LLBS_PPLN_PASS(xf);
      return 1;
    }

    xf->pm.l3_plen = bpf_ntohs(ip6->payload_len);
    xf->pm.l3_len =  xf->pm.l3_plen + sizeof(*ip6);

    xf->l34m.valid = 1;
    xf->l34m.tos = ((ip6->priority << 4) |
                 ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
    xf->l34m.nw_proto = ip6->nexthdr;
    memcpy(&xf->l34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
    memcpy(&xf->l34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

    xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), eth);
    if (xf->l34m.nw_proto == IPPROTO_TCP) {
      struct tcphdr *tcp = DP_ADD_PTR(ip6, sizeof(*ip6));
      if (tcp + 1 > dend) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }

      if (tcp->fin)
        xf->pm.tcp_flags = LLB_TCP_FIN;
      if (tcp->rst)
        xf->pm.tcp_flags |= LLB_TCP_RST;
      if (tcp->syn)
        xf->pm.tcp_flags |= LLB_TCP_SYN;
      if (tcp->psh)
        xf->pm.tcp_flags |= LLB_TCP_PSH;
      if (tcp->ack)
        xf->pm.tcp_flags |= LLB_TCP_ACK;
      if (tcp->urg)
        xf->pm.tcp_flags |= LLB_TCP_URG;

      if (xf->pm.tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
          xf->pm.l4fin = 1;
      }
  
      xf->l34m.source = tcp->source;
      xf->l34m.dest = tcp->dest;
      xf->l34m.seq = tcp->seq;
      xf->l34m.ack = tcp->ack_seq;
    } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
      struct udphdr *udp = DP_ADD_PTR(ip6, sizeof(*ip6));

      if (udp + 1 > dend) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }

      xf->l34m.source = udp->source;
      xf->l34m.dest = udp->dest;
    } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
      struct icmp6hdr *icmp6 = DP_ADD_PTR(ip6, sizeof(*ip6));

      if (icmp6 + 1 > dend) {
        return 0;
      }

      if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
          icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
        xf->l34m.source = icmp6->icmp6_dataun.u_echo.identifier;
        xf->l34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
      } else if (icmp6->icmp6_type >= 133 &&
                 icmp6->icmp6_type <= 137) {
        /* NDisc related */
        LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_PARSER);
        return 1;
      }
    }
  } else if (xf->l2m.dl_type == bpf_htons(ETH_TYPE_LLB)) {
    struct llb_ethheader *llb = DP_TC_PTR(vlh);

    LL_DBG_PRINTK("[PRSR] LLB \n");

#ifdef LL_TC_EBPF
    LLBS_PPLN_DROP(xf);
    return -1;
#endif

    if (DP_TC_PTR(fm_data) + (sizeof(*eth) + sizeof(*llb)) > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    llb = DP_ADD_PTR(fm_data, sizeof(*eth));
    xf->pm.oport = (llb->oport);
    xf->pm.iport = (llb->iport);

    eth = DP_ADD_PTR(fm_data, (int)sizeof(struct llb_ethheader));
    memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
    memcpy(eth->h_source, xf->l2m.dl_src, 6);
    eth->h_proto = llb->next_eth_type;

    if (dp_remove_l2(md, (int)sizeof(*llb))) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

#ifndef LL_TC_EBPF
    if (1) {
      struct ll_xmdi *xm;
      if (bpf_xdp_adjust_meta(md, -(int)sizeof(*xm)) < 0) {
        LL_DBG_PRINTK("[PRSR] adjust meta fail\n");
        LLBS_PPLN_DROP(xf);
        return -1;
      }

      fm_data = DP_PDATA(md);
      xm = DP_TC_PTR(DP_MDATA(md));
      if (xm + 1 >  DP_TC_PTR(fm_data)) {
        LLBS_PPLN_DROP(xf);
        return -1;
      } 

      xm->pi.oport = xf->pm.oport;
      xm->pi.iport = xf->pm.iport;
      xm->pi.skip = 0;
    }
#endif
    //LLBS_PPLN_RDR(xf);
    return 1;
  }

  if (dp_pkt_is_l2mcbc(xf, md) == 1) {
    LLBS_PPLN_TRAP(xf);
    return 1;
  }
  return 0;
}

static int __always_inline
dp_unparse_packet_always_slow(void *ctx,  struct xfi *xf)
{
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

  if (xf->pm.nf & LLB_NAT_SRC) {
    LL_DBG_PRINTK("[DEPR] LL_SNAT 0x%lx:%x\n",
                 xf->nm.nxip4, xf->nm.nxport);
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) || xf->nm.nv6) {
      dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_snat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->pm.nf & LLB_NAT_DST) {
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
    }
  }

  return dp_do_out_vlan(ctx, xf);
}
