/*
 *  llb_dpapi.h: LoxiLB DP Application Programming Interface 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 *  SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) 
 */
#ifndef __LLB_DPAPI_H__
#define __LLB_DPAPI_H__

#define LLB_MGMT_CHANNEL      "llb0"
#define LLB_SECTION_PASS      "xdp_pass"
#define LLB_FP_IMG_DEFAULT    "/opt/loxilb/llb_xdp_main.o"
#define LLB_FP_IMG_BPF        "/opt/loxilb/llb_ebpf_main.o"
#define LLB_FP_IMG_BPF_EGR    "/opt/loxilb/llb_ebpf_emain.o"
#define LLB_SOCK_ADDR_IMG_BPF "/opt/loxilb/llb_kern_sock.o"
#define LLB_SOCK_MAP_IMG_BPF  "/opt/loxilb/llb_kern_sockmap.o"
#define LLB_SOCK_DIR_IMG_BPF  "/opt/loxilb/llb_kern_sockdirect.o"
#define LLB_SOCK_SP_IMG_BPF   "/opt/loxilb/llb_kern_sockstream.o"
#define LLB_DB_MAP_PDIR       "/opt/loxilb/dp/bpf"

#define LLB_MAX_LB_NODES      (2)
#define LLB_MIRR_MAP_ENTRIES  (32)
#define LLB_NH_MAP_ENTRIES    (4*1024)
#define LLB_RTV4_MAP_ENTRIES  (32*1024)
#define LLB_RTV4_PREF_LEN     (48)
#define LLB_CT_MAP_ENTRIES    (256*1024*LLB_MAX_LB_NODES)
#define LLB_ACLV6_MAP_ENTRIES (4*1024)
#define LLB_RTV6_MAP_ENTRIES  (2*1024)
#define LLB_TMAC_MAP_ENTRIES  (2*1024)
#define LLB_DMAC_MAP_ENTRIES  (8*1024)
#define LLB_NATV4_MAP_ENTRIES (4*1024)
#define LLB_NATV4_STAT_MAP_ENTRIES (4*16*1024) /* 16 end-points */
#define LLB_NAT_EP_MAP_ENTRIES (4*1024)
#define LLB_SMAC_MAP_ENTRIES  (LLB_DMAC_MAP_ENTRIES)
#define LLB_FW4_MAP_ENTRIES   (8*1024)
#define LLB_INTERFACES        (512)
#define LLB_PORT_NO           (LLB_INTERFACES-1)
#define LLB_PORT_PIDX_START   (LLB_PORT_NO - 128)
#define LLB_INTF_MAP_ENTRIES  (6*1024)
#define LLB_FCV4_MAP_ENTRIES  (LLB_CT_MAP_ENTRIES)
#define LLB_PGM_MAP_ENTRIES   (8)
#define LLB_FCV4_MAP_ACTS     (DP_SET_TOCP+1)
#define LLB_POL_MAP_ENTRIES   (8*1024)
#define LLB_SESS_MAP_ENTRIES  (20*1024)
#define LLB_PPLAT_MAP_ENTRIES (2048)
#define LLB_PSECS             (8)
#define LLB_MAX_NXFRMS        (32)
#define LLB_CRC32C_ENTRIES    (256)
#define LLB_MAX_MHOSTS        (3)
#define LLB_MAX_SCTP_CHUNKS_INIT (8)
#define LLB_RWR_MAP_ENTRIES   (1024)
#define LLB_SOCK_MAP_SZ       (17*1024)
#define LLB_SOCKID_MAP_SZ     (17*1024)
#define LLB_MAX_HOSTURL_LEN   (256)

#define LLB_DP_MASQ_PGM_ID     (7)
#define LLB_DP_SUNP_PGM_ID2    (6)
#define LLB_DP_CRC_PGM_ID2     (5)
#define LLB_DP_CRC_PGM_ID1     (4)
#define LLB_DP_FW_PGM_ID       (3)
#define LLB_DP_CT_PGM_ID       (2)
#define LLB_DP_PKT_SLOW_PGM_ID (1)
#define LLB_DP_PKT_PGM_ID      (0)

#define LLB_NAT_STAT_CID(rid, aid) ((((rid) & 0xfff) << 4) | (aid & 0xf))

/* Hard-timeout of 40s for fc dp entry */
#define FC_V4_DPTO            (60000000000)

/* Hard-timeout of 2m for fc cp entry */
#define FC_V4_CPTO            (120000000000)

/* Hard-timeout of 30m for ct entry */
#define CT_V4_CPTO            (1800000000000)

/* Hard-timeouts for ct xxx entry */
#define CT_TCP_FN_CPTO        (10000000000)
#define CT_SCTP_FN_CPTO       (10000000000)
#define CT_UDP_FN_CPTO        (5000000000)
#define CT_UDP_EST_CPTO       (10000000000)
#define CT_ICMP_EST_CPTO      (20000000000)
#define CT_ICMP_FN_CPTO       (5000000000)
#define CT_MISMATCH_FN_CPTO   (180000000000)

/* FW Mark values */
#define LLB_MARK_SNAT         (0x80000000)
#define LLB_MARK_SRC          (0x40000000)
#define LLB_MARK_SNAT_EGR     (0x20000000)

#define DP_XADDR_ISZR(a) ((a)[0] == 0 && \
                          (a)[1] == 0 && \
                          (a)[2] == 0 && \
                          (a)[3] == 0)

#define DP_XADDR_CP(a, b)         \
do {                              \
  (a)[0] = (b)[0];                \
  (a)[1] = (b)[1];                \
  (a)[2] = (b)[2];                \
  (a)[3] = (b)[3];                \
} while (0)

#define DP_XADDR_SETZR(a)         \
do {                              \
  (a)[0] = 0;                     \
  (a)[1] = 0;                     \
  (a)[2] = 0;                     \
  (a)[3] = 0;                     \
} while(0)

enum llb_dp_tid {
  LL_DP_INTF_MAP = 0,
  LL_DP_INTF_STATS_MAP,
  LL_DP_BD_STATS_MAP,
  LL_DP_SMAC_MAP,
  LL_DP_TMAC_MAP,
  LL_DP_CT_MAP,
  LL_DP_RTV4_MAP,
  LL_DP_RTV6_MAP,
  LL_DP_NH_MAP,
  LL_DP_DMAC_MAP,
  LL_DP_TX_INTF_MAP,
  LL_DP_MIRROR_MAP,
  LL_DP_TX_INTF_STATS_MAP,
  LL_DP_TX_BD_STATS_MAP,
  LL_DP_PKT_PERF_RING,
  LL_DP_RTV4_STATS_MAP,
  LL_DP_RTV6_STATS_MAP,
  LL_DP_CT_STATS_MAP,
  LL_DP_TMAC_STATS_MAP,
  LL_DP_FCV4_MAP,
  LL_DP_FCV4_STATS_MAP,
  LL_DP_PGM_MAP,
  LL_DP_POL_MAP,
  LL_DP_NAT_MAP,
  LL_DP_NAT_STATS_MAP,
  LL_DP_SESS4_MAP,
  LL_DP_SESS4_STATS_MAP,
  LL_DP_FW4_MAP,
  LL_DP_FW4_STATS_MAP,
  LL_DP_CRC32C_MAP,
  LL_DP_CTCTR_MAP,
  LL_DP_CPU_MAP,
  LL_DP_LCPU_MAP,
  LL_DP_PPLAT_MAP,
  LL_DP_CP_PERF_RING,
  LL_DP_NAT_EP_MAP,
  LL_DP_SOCK_RWR_MAP,
  LL_DP_SOCK_PROXY_MAP,
  LL_DP_MAX_MAP
};

enum {
  DP_SET_DROP            = 0,
  DP_SET_SNAT            = 1,
  DP_SET_DNAT            = 2,
  DP_SET_NEIGH_L2        = 3,
  DP_SET_ADD_L2VLAN      = 4,
  DP_SET_RM_L2VLAN       = 5,
  DP_SET_TOCP            = 6,
  DP_SET_RM_VXLAN        = 7,
  DP_SET_NEIGH_VXLAN     = 8,
  DP_SET_RT_TUN_NH       = 9,
  DP_SET_L3RT_TUN_NH     = 10,
  DP_SET_IFI             = 11,
  DP_SET_NOP             = 12,
  DP_SET_L3_EN           = 13,
  DP_SET_RT_NHNUM        = 14,
  DP_SET_SESS_FWD_ACT    = 15,
  DP_SET_RDR_PORT        = 16,
  DP_SET_POLICER         = 17,
  DP_SET_DO_POLICER      = 18,
  DP_SET_FCACT           = 19,
  DP_SET_DO_CT           = 20,
  DP_SET_RM_GTP          = 21,
  DP_SET_ADD_GTP         = 22,
  DP_SET_NEIGH_IPIP      = 23,
  DP_SET_RM_IPIP         = 24,
  DP_SET_NACT_SESS       = 25,
  DP_SET_FULLPROXY       = 27,
  DP_SET_RT_NHNUM_DFLT   = 28
};

struct dp_cmn_act {
  __u8 act_type;
  __u8 ftrap;
  __u16 oaux;
  __u32 cidx;
  __u16 fwrid;
  __u16 record;
  __u32 mark;
};

struct dp_rt_l2nh_act {
  __u8 dmac[6];
  __u8 smac[6];
  __u16 bd;  
  __u16 rnh_num;
};

#define DP_MAX_ACTIVE_PATHS (4)

struct dp_rt_nh_act {
  __u16 nh_num[DP_MAX_ACTIVE_PATHS];
  __u16 naps;
  __u16 bd;
  __u32 tid;
  struct dp_rt_l2nh_act l2nh;
};

struct dp_rt_l3tun_act {
  __u32 rip;
  __u32 sip;
  __u32 tid;
  __u32 aux;
};

struct dp_rt_tunnh_act {
  struct dp_rt_l3tun_act l3t;
  struct dp_rt_l2nh_act l2nh;
};

struct dp_rdr_act {
  __u16 oport;
  __u16 fr;
};

struct dp_l2vlan_act {
  __u16 vlan;
  __u16 oport;
};

struct dp_sess_act {
  __u32 sess_id;
};

struct dp_nat_act {
  __u32 xip[4];
  __u32 rip[4];
  __u16 xport;
  __u8 fr;
  __u8 doct;
  __u32 rid;
  __u32 aid;
  __u8 nv6;
  __u8 dsr;
  __u8 cdis;
  __u8 nmh;
  __u8 ppv2;
};

#define MIN_DP_POLICER_RATE  (8*1000*1000)  /* 1 MBps = 8 Mbps */

struct dp_pol_stats {
  uint64_t drop_packets;
  uint64_t pass_packets;
};

struct dp_policer_act {
  __u8  trtcm;
  __u8  color_aware;
  __u16 drop_prio; 
  __u32 pad;
  __u32 cbs;
  __u32 ebs;

  /* Internal state data */
  __u32 tok_c;
  __u32 tok_e;
  __u64 toksc_pus;
  __u64 tokse_pus;
  __u64 lastc_uts;
  __u64 laste_uts;
  struct dp_pol_stats ps;
};

struct dp_nh_key {
  __u32 nh_num;
};

struct dp_nh_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_NEIGH_L2
                         */
  union {
    struct dp_rt_l2nh_act rt_l2nh;
    struct dp_rt_tunnh_act rt_tnh;
  };
};

struct dp_rtv6_key {
  struct bpf_lpm_trie_key l;
  union {
    __u32 addr[4]; 
  };
}__attribute__((packed));

struct dp_rtv4_key {
  struct bpf_lpm_trie_key l;
  union {
    __u8  v4k[6];
    __u32 addr; 
  };
}__attribute__((packed));

struct dp_rt_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_RT_NHNUM
                         *  DP_SET_RT_TUN_NH
                         */
  union {
    struct dp_rdr_act port_act;
    struct dp_rt_nh_act rt_nh;
  };
};


struct dp_fcv4_key {
#ifdef HAVE_DP_EXTFC
  __u8  smac[6];
  __u8  dmac[6];
  __u8  in_smac[6];
  __u8  in_dmac[6];
#endif

  __u32 daddr; 
  __u32 saddr; 
  __u16 sport; 
  __u16 dport; 
  __u8  l4proto;
  __u8  pad;
  __u16 in_port;

#ifdef HAVE_DP_EXTFC
  __u8  pad2;
  __u8  in_l4proto;
  __u16 in_sport; 
  __u32 in_daddr; 

  __u32 in_saddr; 
  __u16 in_dport; 
  __u16 bd;
#endif
};

struct dp_fc_tact {
  struct dp_cmn_act ca; /* Possible actions : See below */
  union {
    struct dp_rdr_act port_act;
    struct dp_rt_nh_act nh_act;          /* DP_SET_RM_VXLAN
                                          * DP_SET_RT_TUN_NH
                                          * DP_SET_L3RT_TUN_NH
                                          */
    struct dp_nat_act nat_act;           /* DP_SET_SNAT, DP_SET_DNAT */
    struct dp_rt_l2nh_act nl2;           /* DP_SET_NEIGH_L2 */
    struct dp_rt_tunnh_act ntun;         /* DP_SET_NEIGH_VXLAN,
                                          * DP_SET_NEIGH_IPIP
                                          */
    struct dp_l2vlan_act l2ov;           /* DP_SET_ADD_L2VLAN,
                                          * DP_SET_RM_L2VLAN
                                          */
  };
};

struct dp_fc_tacts {
  struct dp_cmn_act ca;
  __u64 its;
  __u32 zone;
  __u16 pad;
  __u16 pten;
  struct dp_fc_tact fcta[LLB_FCV4_MAP_ACTS];
};

struct dp_dmac_key {
  __u8 dmac[6];
  __u16 bd;
};

struct dp_dmac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_ADD_L2VLAN
                         *  DP_SET_RM_L2VLAN
                         */
  union {
    struct dp_l2vlan_act vlan_act;
    struct dp_rdr_act port_act;
  };
};

struct dp_tmac_key {
  __u8 mac[6];
  __u8 tun_type;
  __u8 pad;
  __u32 tunnel_id;
};

struct dp_tmac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DROP 
                         * DP_SET_TMACT_HIT
                         */
  union {
    struct dp_rt_nh_act rt_nh;
  };
};

struct dp_smac_key {
  __u8 smac[6];
  __u16 bd;
};

struct dp_smac_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DROP 
                         * DP_SET_TOCP
                         * DP_SET_NOP
                         */
};

struct intf_key {
  __u32 ifindex;
  __u16 ing_vid;
  __u16 pad;
};

struct dp_intf_tact_set_ifi {
  __u16 xdp_ifidx;
  __u16 zone;
  __u16 bd;
  __u16 mirr;
  __u16 polid;
  __u8  pprop;
#define DP_PTEN_ALL   2
#define DP_PTEN_TRAP  1
#define DP_PTEN_DIS   0
  __u8  pten;
  __u8  r[4];
};

struct dp_intf_tact {
  struct dp_cmn_act ca;
  union {
    struct dp_intf_tact_set_ifi set_ifi;
  };
};

struct dp_intf_map {
	struct intf_key key;
  struct dp_intf_tact acts;
};

struct dp_mirr_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_NEIGH_VXLAN
                         * DP_SET_ADD_L2VLAN
                         * DP_SET_RM_L2VLAN
                         */
  union {
    struct dp_rt_tunnh_act rt_tnh;
    struct dp_l2vlan_act vlan_act;
    struct dp_rdr_act port_act;
  };
};

struct dp_pol_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         * DP_SET_DO_POLICER
                         */
  struct bpf_spin_lock lock;
  union {
    struct dp_policer_act pol;
  };
};

struct sock_rwr_key {
#define vip4 vip[0]
  __u32 vip[4];
  __u16 port;
  __u16 res;
};

struct sock_rwr_action {
  __u16 rw_port;
  __u16 res;
};

struct dp_pb_stats {
  uint64_t bytes;
  uint64_t packets;
};
typedef struct dp_pb_stats dp_pb_stats_t;

#define DP_ST_LTO  (10000000000ULL)

struct dp_pbc_stats {
  dp_pb_stats_t st;
  uint64_t lts_used;
  int used;
};
typedef struct dp_pbc_stats dp_pbc_stats_t;

/* Connection tracking related defines */
typedef enum {
  CT_DIR_IN = 0,
  CT_DIR_OUT,
  CT_DIR_MAX
} ct_dir_t;

typedef enum {
  CT_STATE_NONE = 0x0,
  CT_STATE_REQ  = 0x1,
  CT_STATE_REP  = 0x2,
  CT_STATE_EST  = 0x4,
  CT_STATE_FIN  = 0x8,
  CT_STATE_DOR  = 0x10
} ct_state_t;

typedef enum {
  CT_FSTATE_NONE = 0x0,
  CT_FSTATE_SEEN = 0x1,
  CT_FSTATE_DOR  = 0x2
} ct_fstate_t;

typedef enum {
  CT_SMR_ERR    = -1,
  CT_SMR_INPROG = 0,
  CT_SMR_EST    = 1,
  CT_SMR_UEST   = 2,
  CT_SMR_FIN    = 3,
  CT_SMR_CTD    = 4,
  CT_SMR_UNT    = 100,
  CT_SMR_INIT   = 200,
} ct_smr_t;

#define CT_TCP_FIN_MASK (CT_TCP_FINI|CT_TCP_FINI2|CT_TCP_FINI3|CT_TCP_CW)
#define CT_TCP_SYNC_MASK (CT_TCP_SS|CT_TCP_SA)

typedef enum {
  CT_TCP_CLOSED = 0x0,
  CT_TCP_SS     = 0x1,
  CT_TCP_SA     = 0x2,
  CT_TCP_EST    = 0x4,
  CT_TCP_FINI   = 0x10,
  CT_TCP_FINI2  = 0x20,
  CT_TCP_FINI3  = 0x40,
  CT_TCP_CW     = 0x80,
  CT_TCP_ERR    = 0x100,
  CT_TCP_PEST   = 0x200,
} ct_tcp_state_t;

typedef struct {
  __u16 hstate;
#define CT_TCP_INIT_ACK_THRESHOLD 3
  __u8 init_acks;
  __u8 ppv2;
  __u32 seq;
  __be32 pack;
  __be32 pseq;
} ct_tcp_pinfd_t;

typedef struct {
  ct_tcp_state_t state;
  ct_dir_t fndir;
  ct_tcp_pinfd_t tcp_cts[CT_DIR_MAX];
} ct_tcp_pinf_t;


#define CT_UDP_FIN_MASK (CT_UDP_FINI)

typedef enum {
  CT_UDP_CNI    = 0x0,
  CT_UDP_UEST   = 0x1,
  CT_UDP_EST    = 0x2,
  CT_UDP_FINI   = 0x8,
  CT_UDP_CW     = 0x10,
} ct_udp_state_t;

typedef struct {
  __u16 state;
#define CT_UDP_CONN_THRESHOLD 4
  __u16 pkts_seen;
  __u16 rpkts_seen;
   ct_dir_t fndir;
} ct_udp_pinf_t;

typedef enum {
  CT_ICMP_CLOSED= 0x0,
  CT_ICMP_REQS  = 0x1,
  CT_ICMP_REPS  = 0x2,
  CT_ICMP_FINI  = 0x4,
  CT_ICMP_DUNR  = 0x8,
  CT_ICMP_TTL   = 0x10,
  CT_ICMP_RDR   = 0x20,
  CT_ICMP_UNK   = 0x40,
} ct_icmp_state_t;

typedef struct {
  __u32 nh;
  __u32 odst;
  __u32 osrc;
  __be32 mh_host[LLB_MAX_MHOSTS+1];
} ct_sctp_pinfd_t;

#define CT_SCTP_FIN_MASK (CT_SCTP_SHUT|CT_SCTP_SHUTA|CT_SCTP_SHUTC|CT_SCTP_ABRT)
#define CT_SCTP_INIT_MASK (CT_SCTP_INIT|CT_SCTP_INITA|CT_SCTP_COOKIE|CT_SCTP_COOKIEA)

typedef enum {
  CT_SCTP_CLOSED  = 0x0,
  CT_SCTP_INIT    = 0x1,
  CT_SCTP_INITA   = 0x2,
  CT_SCTP_COOKIE  = 0x4,
  CT_SCTP_COOKIEA = 0x10,
  CT_SCTP_PRE_EST = 0x20,
  CT_SCTP_EST     = 0x40,
  CT_SCTP_SHUT    = 0x80,
  CT_SCTP_SHUTA   = 0x100,
  CT_SCTP_SHUTC   = 0x200,
  CT_SCTP_ERR     = 0x400,
  CT_SCTP_ABRT    = 0x800
} ct_sctp_state_t;

typedef struct {
  ct_sctp_state_t state;
  ct_dir_t fndir;
  uint32_t itag;
  uint32_t otag;
  uint32_t cookie;
  ct_sctp_pinfd_t sctp_cts[CT_DIR_MAX];
} ct_sctp_pinf_t;

typedef struct {
  uint8_t state;
  uint8_t errs;
  uint16_t lseq;
} ct_icmp_pinf_t;

typedef struct {
  ct_state_t state;
} ct_l3inf_t;

typedef struct {
  union {
    ct_tcp_pinf_t t;
    ct_udp_pinf_t u;
    ct_icmp_pinf_t i;
    ct_sctp_pinf_t s;
  };
  __u16 frag;
  __u16 npmhh;
  __u32 pmhh[4];
  ct_l3inf_t l3i;
} ct_pinf_t;

#define nat_xip4 nat_xip[0]
#define nat_rip4 nat_rip[0]

struct mf_xfrm_inf
{
  /* LLB_NAT_XXX flags */
  uint8_t nat_flags;
  uint8_t inactive;
  uint8_t wprio;
  uint8_t nv6;
  uint8_t dsr;
  uint8_t mhon:4;
  uint8_t mhs:4;
  uint16_t nat_xport;
  uint32_t nat_xip[4];
  uint32_t nat_rip[4];
  uint16_t osp;
  uint16_t odp;
};
typedef struct mf_xfrm_inf nxfrm_inf_t;

struct dp_ct_dat {
  __u16 rid;
  __u16 aid;
  __u32 nid;
  ct_pinf_t pi;
  ct_dir_t dir;
  ct_smr_t smr;
  nxfrm_inf_t xi;
  dp_pb_stats_t pb;
};

struct dp_ct_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_NOP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_RT_NHNUM
                         *  DP_SET_SESS_FWD_ACT
                         */
  struct bpf_spin_lock lock;
  struct dp_ct_dat ctd;
  __u64 ito;            /* Inactive timeout */
  __u64 lts;            /* Last used timestamp */
  union {
    struct dp_rdr_act port_act;
    struct dp_sess_act pdr_sess_act;
    struct dp_rt_nh_act rt_nh;
    struct dp_nat_act nat_act;
  };
};

struct dp_ct_tact_set {
  uint16_t wp;
  uint16_t fc;
  uint32_t tc;
  struct dp_ct_tact tact;
};

#define CT_MAX_ACT_SET         16 

#define DP_SET_LB_NONE         0
#define DP_SET_LB_WPRIO        1
#define DP_SET_LB_RR           2

struct dp_ct_tacts {
  uint16_t num_acts;
  uint16_t lb_type;
  uint32_t rdata;
  struct dp_ct_tact_set act_set[CT_MAX_ACT_SET];
};
typedef struct dp_ct_tacts dp_ct_tacts_t;

struct dp_ct_key {
  __u32 daddr[4];
  __u32 saddr[4];
  __u16 sport;
  __u16 dport;
  __u16 zone;
  __u8  l4proto;
  __u8  v6;
  __u32 ident;
  __u32 type;
};

struct dp_proxy_ct_ent {
  __u32 rid;
  __u32 aid;
  struct dp_ct_key ct_in;
  struct dp_ct_key ct_out;
  struct dp_pb_stats st_in;
  struct dp_pb_stats st_out;
};

struct dp_fwv4_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_NOP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_FW_MARK
                         */
  union {
    struct dp_rdr_act port_act;
    struct dp_nat_act nat_act;
  };
};

struct dp_fwv4_ent {
	struct pdi_key k;
  struct dp_fwv4_tact fwa;
};

struct dp_nat_key {
  __u32 daddr[4];
  __u16 dport;
  __u16 zone;
  __u32 mark;
  __u16 l4proto;
  __u16 v6;
};

#define NAT_LB_SEL_RR   0
#define NAT_LB_SEL_HASH 1
#define NAT_LB_SEL_PRIO 2
#define NAT_LB_SEL_RR_PERSIST 3
#define NAT_LB_SEL_LC 4
#define NAT_LB_SEL_N2 5
#define NAT_LB_SEL_N3 6

#define NAT_LB_PERSIST_TIMEOUT (10800000000000ULL)

#define SEC_MODE_NONE 0
#define SEC_MODE_HTTPS 1
#define SEC_MODE_HTTPS_E2E 2

#define NAT_LB_OP_CHKSRC 0x1

struct dp_proxy_tacts {
  struct dp_cmn_act ca;
  uint64_t ito;
  uint64_t pto;
  struct bpf_spin_lock lock;
  uint8_t nxfrm;
  uint8_t opflags;
  uint8_t cdis;
  uint8_t npmhh;
  uint16_t sel_hint;
  uint8_t sel_type;
  uint8_t sec_mode;
  uint8_t ppv2;
  uint32_t pmhh[LLB_MAX_MHOSTS];
  struct mf_xfrm_inf nxfrms[LLB_MAX_NXFRMS];
  uint8_t host_url[LLB_MAX_HOSTURL_LEN];
  uint64_t lts;
  uint64_t base_to;
};

struct dp_nat_epacts {
  struct dp_cmn_act ca;
  struct bpf_spin_lock lock;
  uint32_t active_sess[LLB_MAX_NXFRMS];
};

/* This is currently based on ULCL classification scheme */
struct dp_sess4_key {
  __u32 daddr;
  __u32 saddr;
  __u32 teid;
  __u32 r;
};

struct dp_sess_tact {
  struct dp_cmn_act ca;
  uint8_t qfi; 
  uint8_t r1;
  uint16_t r2;
  uint32_t rip;
  uint32_t sip;
  uint32_t teid;
};

struct dp_ct_ctrtact {
  struct dp_cmn_act ca; /* Possible actions :
                         * None (just place holder)
                         */
  struct bpf_spin_lock lock;
  __u32 start;
  __u32 counter;
  __u32 entries;
};

struct llb_sockmap_key {
  __be32 dip;
  __be32 sip;
  __be32 dport;
  __be32 sport;
};

struct sock_str_key {
  __u32 xip;
  __u16 xport;
  __u16 res;
};

struct sock_str_val {
  __u32 start;
  __u32 num;
};

struct ll_dp_pmdi {
  __u32 ifindex;
  __u16 dp_inport;
  __u16 dp_oport;
  __u32 rcode;
  __u16 table_id;
  __u16 phit ;
  __u32 pkt_len;
  __u32 resolve_ip;
  uint8_t data[];
}; 

struct ll_dp_map_notif {
  int addop;
  char map_name[16];
  int key_len;
  void *key;
  int val_len;
  void *val;
};
typedef struct ll_dp_map_notif ll_dp_map_notif_t;

struct dp_map_ita {
  void *next_key;
  size_t key_sz;
  void *val;
  void *uarg;
};
typedef struct dp_map_ita dp_map_ita_t;

void goMapNotiHandler(struct ll_dp_map_notif *mn);

#define __force __attribute__((force))

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#define DP_ADD_PTR(x, len) ((void *)(((uint8_t *)((long)x)) + (len)))
#define DP_TC_PTR(x) ((void *)((long)x))
#define DP_DIFF_PTR(x, y) (((uint8_t *)DP_TC_PTR(x)) - ((uint8_t *)DP_TC_PTR(y)))

/* Policer map stats update callback */
typedef void (*dp_pts_cb_t)(uint32_t idx, struct dp_pol_stats *ps);
/* Map stats update callback */
typedef void (*dp_ts_cb_t)(uint32_t idx, uint64_t bc, uint64_t pc);
/* Map stats idx valid check callback */
typedef int (*dp_tiv_cb_t)(int tid, uint32_t idx);
/* Map walker */
typedef int (*dp_map_walker_t)(int tid, void *key, void *arg);

int llb_map2fd(int t);
int llb_fetch_map_stats_cached(int tbl, uint32_t index, int raw, void *bc, void *pc);
void llb_age_map_entries(int tbl);
void llb_trigger_get_proxy_entries(void);
void llb_collect_map_stats(int tbl);
int llb_fetch_pol_map_stats(int tid, uint32_t e, void *ppass, void *pdrop);
void llb_clear_map_stats(int tbl, __u32 idx);
int llb_add_map_elem(int tbl, void *k, void *v);
int llb_del_map_elem_wval(int tbl, void *k, void *v);
int llb_del_map_elem(int tbl, void *k);
void llb_map_loop_and_delete(int tbl, dp_map_walker_t cb, dp_map_ita_t *it);
int llb_dp_link_attach(const char *ifname, const char *psec, int mp_type, int unload);
void llb_unload_kern_all(void);
void llb_xh_lock(void);
void llb_xh_unlock(void);

#endif /* __LLB_DPAPI_H__ */
