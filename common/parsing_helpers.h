/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define ETH_TYPE_ETH2(x) ((x) >= bpf_htons(1536))

typedef enum {
  DP_PRET_FAIL  = -1,
  DP_PRET_OK    =  0,
  DP_PRET_TRAP  =  1,
  DP_PRET_PASS  =  2
}dpret_t;

/* Parser to help ebpf packet parsing */
struct parser {
  __u8 inp:1;
  __u8 skip_l2:1;
  __u8 skip_v6:1;
  __u8 res:5;
  void *start;
  void *dbegin;
  void *dend;
};

/* Parser to help gtp ebpf packer parsing */
struct gtp_parser {
  struct gtp_v1_hdr *gh;
  struct gtp_v1_ehdr *geh;
  void *nh;
  void *gtp_next;
  __u8 hlen;
  __u8 *nhl;
  __u8 *neh;
  __u8 elen;
};

#define VLAN_VID_MASK  0x0fff
#define VLAN_PCP_MASK  0xe000
#define VLAN_PCP_SHIFT 13

/* Allow users of header file to redefine VLAN max depth */
#ifndef MAX_STACKED_VLANS
#define MAX_STACKED_VLANS 3
#endif

/*
 *	struct vlanhdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlanhdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

#define ARP_ETH_HEADER_LEN 28

/*
 *	struct arp_ethhdr - arp header
 *	@ar_hrd: Hardware type
 *	@ar_pro: Protocol type
 *	@ar_hln: Protocol address len
 *	@ar_op:  ARP opcode
 *	@ar_sha: Sender hardware/mac address
 *	@ar_spa: Sender protocol address
 *	@ar_tha: Target hardware/mac address
 *	@ar_tpa: Target protocol address
 */
struct arp_ethhdr {
  __be16    ar_hrd;
  __be16    ar_pro;
  __u8      ar_hln;
  __u8      ar_pln;
  __be16    ar_op;
  __u8      ar_sha[6];
  __be32    ar_spa;
  __u8      ar_tha[6];
  __be32    ar_tpa;
} __attribute__((packed));

/* LLB L2 header type */
#define ETH_TYPE_LLB 0x9999

/*
 *  struct llb_ethhdr - header for internal communication
 *  @iport: input port
 *  @oport: output port
 *  @mmap:  missed map
 *  @rcode: return code
 *  @ntype: next header type
 */
struct llb_ethhdr {
  __be16 iport;
  __be16 oport;
  __u8   mmap;
  __u8   rcode;
  __be16 ntype;
} __attribute__((packed));

#define VXLAN_OUDP_DPORT (4789)
#define VXLAN_OUDP_SPORT (4788)
#define VXLAN_VI_FLAG_ON (bpf_htonl(0x08 << 24))

/*
 *  struct vxlanhdr - vxlan header
 *  @vx_flags: flags
 *  @vx_vni:   vxlan vni info
 */
struct vxlanhdr {
    __be32 vx_flags;
    __be32 vx_vni;
}__attribute__((packed));

/*
 * struct icmp_cmnhdr - represents the common part of the icmphdr and icmp6hdr
 * @type:  icmp packet type
 * @code:  icmp code
 * @cksum: icmp checksum
 */
struct icmp_cmnhdr {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};

/* IP flags */
#define IP_CE		  0x8000		/* Flag: "Congestion"		*/
#define IP_DF		  0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		  0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

static __always_inline int ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}

static __always_inline int ip_is_first_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & bpf_htons(IP_OFFSET)) == 0;
}

static __always_inline int proto_is_vlan(__be16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
  __be32 check = iph->check;
  check += bpf_htons(0x0100);
  iph->check = (__be16)(check + (check >= 0xFFFF));
  return --iph->ttl;
}

static inline int ipv6_addr_is_multicast(const struct in6_addr *addr)
{
  return (addr->s6_addr32[0] & bpf_htonl(0xFF000000)) == bpf_htonl(0xFF000000);
}

static __always_inline __be16
csum_fold_helper(__be32 csum)
{
  return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void
ipv4_csum(void *data_start,
          int data_size,
          __be32 *csum)
{
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

static __always_inline void
ipv4_l4_csum(void *data_start, __be32 data_size,
             __u64 *csum, struct iphdr *iph) {
  __be32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  // __builtin_bswap32 equals to htonl()
  tmp = __builtin_bswap32((__be32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__be32), *csum);
  tmp = __builtin_bswap32((__be32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

#define GTPU_UDP_SPORT (2152)
#define GTPU_UDP_DPORT (2152)
#define GTPC_UDP_DPORT (2153)
  
#define GTP_HDR_LEN    (8)
#define GTP_VER_1      (0x1)
#define GTP_EXT_FM     (0x4)
#define GTP_MT_TPDU    (0xff)
  
/*
 * struct gtp_v1_hdr - GTPv1 header
 */
struct gtp_v1_hdr {
#if defined(__BIG_ENDIAN_BITFIELD)
  __u8    ver:3;
  __u8    pt:1;
  __u8    res:1;
  __u8    espn:3;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
  __u8    espn:3;
  __u8    res:1;
  __u8    pt:1;
  __u8    ver:3;
#else
#error  "Please fix byteorder"
#endif
  __u8    mt;
  __be16  mlen;
  __be32  teid;
};
  
#define GTP_MAX_EXTH    2
#define GTP_NH_PDU_SESS 0x85

/*
 * struct gtp_v1_ehdr - GTPv1 extension header
 */
struct gtp_v1_ehdr {
  __be16  seq;
  __u8    npdu;
  __u8    next_hdr;
};

#define GTP_PDU_SESS_UL 1
#define GTP_PDU_SESS_DL 0

/*
 * struct gtp_pdu_sess_hdr - GTP common PDU session header
 */
struct gtp_pdu_sess_cmnhdr {
  __u8    len;
#if defined(__BIG_ENDIAN_BITFIELD)
  __u8    pdu_type:4;
  __u8    res:4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
  __u8    res:4;
  __u8    pdu_type:4;
#else
#error  "Please fix byteorder"
#endif
};

/*
 * struct gtp_dl_pdu_sess_hdr - GTP DL PDU session header
 */
struct gtp_dl_pdu_sess_hdr {
  struct gtp_pdu_sess_cmnhdr cmn;
#if defined(__BIG_ENDIAN_BITFIELD)
  __u8    ppp:1;
  __u8    rqi:1;
  __u8    qfi:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
  __u8    qfi:6;
  __u8    rqi:1;
  __u8    ppp:1;
#else
#error  "Please fix byteorder"
#endif
  __u8    next_hdr;
};

/*
 * struct gtp_ul_pdu_sess_hdr - GTP UL PDU session header
 */
struct gtp_ul_pdu_sess_hdr {
  struct gtp_pdu_sess_cmnhdr cmn;
#if defined(__BIG_ENDIAN_BITFIELD)
  __u8    res:2;
  __u8    qfi:6;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
  __u8    qfi:6;
  __u8    res:2;
#else
#error  "Please fix byteorder"
#endif
  __u8    next_hdr;
};

/*
 * struct sctphdr - SCTP header
 */
struct sctphdr {
	__be16 source;
	__be16 dest;
	__be32 vtag;
	__le32 checksum;
};

#define SCTP_INIT_CHUNK     1
#define SCTP_INIT_CHUNK_ACK 2
#define SCTP_HB_REQ         4
#define SCTP_HB_ACK         5
#define SCTP_ABORT          6
#define SCTP_SHUT           7
#define SCTP_SHUT_ACK       8
#define SCTP_ERROR          9
#define SCTP_COOKIE_ECHO   10
#define SCTP_COOKIE_ACK    11
#define SCTP_SHUT_COMPLETE 14
 
/*
 * struct sctp_dch - SCTP chunk
 */
struct sctp_dch {
	__u8 type;
	__u8 flags;
	__be16 len;
};

#define SCTP_IPV4_ADDR_PARAM  0x5
#define SCTP_MAX_BIND_ADDRS   3

struct sctp_param {
  __be16 type;
  __be16 len;
};

/*
 * struct sctp_init_ch - SCTP init chunk
 */
struct sctp_init_ch {
  __be32 tag;
  __be32 adv_rwc;
  __be16 n_ostr; 
  __be16 n_istr; 
  __be32 init_tsn;
};

struct sctp_cookie {
  __be32 cookie;
};

struct mkrt_args {
  uint32_t seq;
  uint8_t fin:1;
  uint8_t syn:1;
  uint8_t rst:1;
  uint8_t psh:1;
  uint8_t ack:1;
  uint8_t urg:1;
  uint8_t res:2;
};

struct mkr_args {
  uint8_t  v6;
  uint32_t dip[4];
  uint32_t sip[4];
  uint16_t sport;
  uint16_t dport;
  uint8_t  protocol;

  union {
    struct mkrt_args t;
  };
};

int create_raw_tcp(void *packet, size_t *plen, struct mkr_args *args);
int create_send_raw_tcp(struct mkr_args *args);

#endif /* __PARSING_HELPERS_H */
