/*
 *  llb_dp_cdefs.h: Loxilb eBPF/XDP utility functions 
 *  Copyright (c) 2022-2025 LoxiLB Authors
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#ifndef __LLB_DP_CDEFS_H__
#define __LLB_DP_CDEFS_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_pdi.h"
#include "../common/llb_dp_mdi.h"
#include "../common/llb_dpapi.h"

#ifndef __stringify
# define __stringify(X)   #X
#endif

#ifndef __section
# define __section(NAME)            \
  __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)          \
  __section(__stringify(ID) "/" __stringify(KEY))
#endif

#define PGM_ENT0    0
#define PGM_ENT1    1

#define SAMPLE_SIZE 64ul

#ifndef lock_xadd
#define lock_xadd(ptr, val)              \
   ((void)__sync_fetch_and_add(ptr, val))
#endif

struct ll_xmdpi
{
  __u16 iport;
  __u16 oport;
  __u32 skip;
};

struct ll_xmdi {
  union {
      __u64 xmd;
    struct ll_xmdpi pi;
  };
} __attribute__((aligned(4)));

#define HAVE_DP_BUF_FIXUP 1
#define LLB_MARK_SKB_FIXUP 0xbeefdead
#define LLB_SKB_FIXUP_LEN 1000
#define LLB_SKB_MIN_DPA_LEN 80

#ifdef HAVE_LEGACY_BPF_MAPS

struct bpf_map_def SEC("maps") intf_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct intf_key),
  .value_size = sizeof(struct dp_intf_tact),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") intf_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") bd_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index bd_id */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") pkt_ring = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = MAX_REAL_CPUS,
};

struct bpf_map_def SEC("maps") cp_ring = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = MAX_REAL_CPUS,
};

struct bpf_map_def SEC("maps") pkts = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct ll_dp_pmdi),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") fcas = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fc_tacts),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") xfis = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct xfi),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") tx_intf_map = {
  .type = BPF_MAP_TYPE_DEVMAP,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") tx_intf_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") tx_bd_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index bd_id */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") smac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_smac_key),
  .value_size = sizeof(struct dp_smac_tact),
  .max_entries = LLB_SMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") dmac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_dmac_key),
  .value_size = sizeof(struct dp_dmac_tact),
  .max_entries = LLB_DMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") tmac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_tmac_key),
  .value_size = sizeof(struct dp_tmac_tact),
  .max_entries = LLB_TMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") tmac_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* tmac index */
  .value_size = sizeof(struct ll_dp_pmdi),
  .max_entries = LLB_TMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nh_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(struct dp_nh_key),
  .value_size = sizeof(struct dp_nh_tact),
  .max_entries = LLB_NH_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") ct_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_ct_key),
  .value_size = sizeof(struct dp_ct_tact),
  .max_entries = LLB_CT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") ct_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_CT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nat_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_nat_key),
  .value_size = sizeof(struct dp_proxy_tacts),
  .max_entries = LLB_NATV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nat_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_NATV4_STAT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nat_ep_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_nat_epacts),
  .max_entries = LLB_NAT_EP_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v4_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv4_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_RTV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v6_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv6_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV6_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v6_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_RTV6_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") mirr_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_mirr_tact),
  .max_entries = LLB_MIRR_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") sess_v4_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_sess4_key),
  .value_size = sizeof(struct dp_sess_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_SESS_MAP_ENTRIES 
};

struct bpf_map_def SEC("maps") sess_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_SESS_MAP_ENTRIES 
};

struct bpf_map_def SEC("maps") fc_v4_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_fcv4_key),
  .value_size = sizeof(struct dp_fc_tacts),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_FCV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fc_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_FCV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fw_v4_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fwv4_ent),
  .max_entries = LLB_FW4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fw_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_FW4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fw_v6_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fwv6_ent),
  .max_entries = LLB_FW6_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") pgm_tbl = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries =  LLB_PGM_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") polx_map = { 
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_pol_tact),
  .max_entries =  LLB_POL_MAP_ENTRIES 
}; 

struct bpf_map_def SEC("maps") xfck = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct dp_fcv4_key),
  .max_entries = 1,
};

#else /* New BTF definitions */

struct intf_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct intf_key);
        __type(value,       struct dp_intf_tact);
        __uint(max_entries, LLB_INTERFACES);
} intf_map SEC(".maps");

struct intf_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTERFACES);
} intf_stats_map SEC(".maps");

struct bd_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} bd_stats_map SEC(".maps");

struct pkt_ring_d {
        __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __type(key,         int);
        __type(value,       __u32);
        __uint(max_entries, MAX_REAL_CPUS);
} pkt_ring SEC(".maps");

struct cp_ring_d {
        __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __type(key,         int);
        __type(value,       __u32);
        __uint(max_entries, MAX_REAL_CPUS);
} cp_ring SEC(".maps");

struct pkts_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct ll_dp_pmdi);
        __uint(max_entries, 1);
} pkts SEC(".maps");

struct fcas_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_fc_tacts);
        __uint(max_entries, 1);
} fcas SEC(".maps");

struct xfis_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct xfi);
        __uint(max_entries, 1);
} xfis SEC(".maps");

struct tx_intf_map_d {
        __uint(type,        BPF_MAP_TYPE_DEVMAP);
        __type(key,         int);
        __type(value,       int);
        __uint(max_entries, LLB_INTERFACES);
} tx_intf_map SEC(".maps");

struct tx_intf_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} tx_intf_stats_map SEC(".maps");

struct tx_bd_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} tx_bd_stats_map SEC(".maps");

struct smac_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_smac_key);
        __type(value,       struct dp_smac_tact);
        __uint(max_entries, LLB_SMAC_MAP_ENTRIES);
} smac_map SEC(".maps");

struct dmac_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_dmac_key);
        __type(value,       struct dp_dmac_tact);
        __uint(max_entries, LLB_DMAC_MAP_ENTRIES);
} dmac_map SEC(".maps");

struct tmac_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_tmac_key);
        __type(value,       struct dp_tmac_tact);
        __uint(max_entries, LLB_TMAC_MAP_ENTRIES);
} tmac_map SEC(".maps");

struct tmac_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_TMAC_MAP_ENTRIES);
} tmac_stats_map SEC(".maps");

struct nh_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         struct dp_nh_key);
        __type(value,       struct dp_nh_tact);
        __uint(max_entries, LLB_NH_MAP_ENTRIES);
} nh_map SEC(".maps");

struct ct_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_ct_key);
        __type(value,       struct dp_ct_tact);
        __uint(max_entries, LLB_CT_MAP_ENTRIES);
} ct_map SEC(".maps");

struct ct_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_CT_MAP_ENTRIES);
} ct_stats_map SEC(".maps");

struct nat_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_nat_key);
        __type(value,       struct dp_proxy_tacts);
        __uint(max_entries, LLB_NATV4_MAP_ENTRIES);
} nat_map SEC(".maps");

struct nat_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_NATV4_STAT_MAP_ENTRIES);
} nat_stats_map SEC(".maps");

struct nat_ep_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_nat_epacts);
        __uint(max_entries, LLB_NAT_EP_MAP_ENTRIES);
} nat_ep_map SEC(".maps");

struct rt_v4_map_d {
        __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
        __type(key,         struct dp_rtv4_key);
        __type(value,       struct dp_rt_tact);
        __uint(map_flags,   BPF_F_NO_PREALLOC);
        __uint(max_entries, LLB_RTV4_MAP_ENTRIES);
} rt_v4_map SEC(".maps");

struct rt_v4_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_RTV4_MAP_ENTRIES);
} rt_v4_stats_map SEC(".maps");

struct rt_v6_map_d {
        __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
        __type(key,         struct dp_rtv6_key);
        __type(value,       struct dp_rt_tact);
        __uint(map_flags,   BPF_F_NO_PREALLOC);
        __uint(max_entries, LLB_RTV6_MAP_ENTRIES);
} rt_v6_map SEC(".maps");

struct rt_v6_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_RTV6_MAP_ENTRIES);
} rt_v6_stats_map SEC(".maps");

struct mirr_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_mirr_tact);
        __uint(max_entries, LLB_MIRR_MAP_ENTRIES);
} mirr_map SEC(".maps");

struct sess_v4_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_sess4_key);
        __type(value,       struct dp_sess_tact);
        __uint(max_entries, LLB_SESS_MAP_ENTRIES);
} sess_v4_map SEC(".maps");

struct sess_v4_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_SESS_MAP_ENTRIES);
} sess_v4_stats_map SEC(".maps");

struct fc_v4_map_d {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_fcv4_key);
        __type(value,       struct dp_fc_tacts);
        __uint(max_entries, LLB_FCV4_MAP_ENTRIES);
} fc_v4_map SEC(".maps");

struct fc_v4_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_FCV4_MAP_ENTRIES);
} fc_v4_stats_map SEC(".maps");

struct fw_v4_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_fwv4_ent);
        __uint(max_entries, LLB_FW4_MAP_ENTRIES);
} fw_v4_map SEC(".maps");

struct fw_stats_map_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_FW4_MAP_ENTRIES + LLB_FW6_MAP_ENTRIES);
} fw_stats_map SEC(".maps");

struct fw_v6_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_fwv6_ent);
        __uint(max_entries, LLB_FW4_MAP_ENTRIES);
} fw_v6_map SEC(".maps");

struct pgm_tbl_d {
        __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
        __type(key,         __u32);
        __type(value,       __u32);
        __uint(max_entries, LLB_PGM_MAP_ENTRIES);
} pgm_tbl SEC(".maps");

struct polx_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pol_tact);
        __uint(max_entries, LLB_POL_MAP_ENTRIES);
} polx_map SEC(".maps");

struct xfck_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct dp_fcv4_key);
        __uint(max_entries, 1);
} xfck SEC(".maps");

struct crc32c_map_d {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       __u32);
        __uint(max_entries, LLB_CRC32C_ENTRIES);
} crc32c_map SEC(".maps");

struct cpu_map_d {
	      __uint(type,        BPF_MAP_TYPE_CPUMAP);
	      __type(key,         __u32);
	      __type(value,       __u32);
	      __uint(max_entries, MAX_REAL_CPUS);
} cpu_map SEC(".maps");

struct live_cpu_map_d {
	      __uint(type,        BPF_MAP_TYPE_ARRAY);
	      __type(key,         __u32);
	      __type(value,       __u32);
	      __uint(max_entries, MAX_REAL_CPUS);
} live_cpu_map SEC(".maps");

struct pplat_map_d {
	      __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
	      __type(key,         __u32);
	      __type(value,       struct dp_pb_stats);
	      __uint(max_entries, LLB_PPLAT_MAP_ENTRIES);
} pplat_map SEC(".maps");

struct xctk_d {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_ct_tact);
        __uint(max_entries, 2);
} xctk SEC(".maps");


#endif

static void __always_inline
dp_do_map_stats(void *ctx,
                struct xfi *xf,
                int xtbl,
                int cidx)
{
  struct dp_pb_stats *pb;
  struct dp_pb_stats pb_new;
  void *map = NULL;
  int key = cidx;

  switch (xtbl) {
  case LL_DP_RTV4_STATS_MAP:
    map = &rt_v4_stats_map;
    break;
  case LL_DP_RTV6_STATS_MAP:
    map = &rt_v6_stats_map;
    break;
  case LL_DP_CT_STATS_MAP:
    map = &ct_stats_map;
    break;
  case LL_DP_INTF_STATS_MAP:
    map = &intf_stats_map;
    break;
  case LL_DP_TX_INTF_STATS_MAP:
    map = &tx_intf_stats_map;
    break;
  case LL_DP_BD_STATS_MAP:
    map = &bd_stats_map;
    break;
  case LL_DP_TX_BD_STATS_MAP:
    map = &tx_bd_stats_map;
    break;
  case LL_DP_TMAC_STATS_MAP:
    map = &tmac_stats_map;
    break;
  case LL_DP_SESS4_STATS_MAP:
    map = &sess_v4_stats_map;
    break;
  case LL_DP_NAT_STATS_MAP:
    map = &nat_stats_map;
    break;
  case LL_DP_FW_STATS_MAP:
    map = &fw_stats_map;
    break;
  case LL_DP_PPLAT_MAP:
    map = &pplat_map;
    break;
  default:
    return;
  }

  pb = bpf_map_lookup_elem(map, &key);
  if (pb) {
    pb->bytes += xf->pm.l3_plen;
    pb->packets += 1;
    return;
  }

  pb_new.bytes =  xf->pm.l3_plen;
  pb_new.packets = 1;

  bpf_map_update_elem(map, &key, &pb_new, BPF_ANY);

  return;
}

static void __always_inline
dp_ipv4_new_csum(struct iphdr *iph)
{
  __u16 *iph16 = (__u16 *)iph;
  __u32 csum;
  int i;

  iph->check = 0;

#pragma clang loop unroll(full)
  for (i = 0, csum = 0; i < sizeof(*iph) >> 1; i++)
    csum += *iph16++;

  iph->check = ~((csum & 0xffff) + (csum >> 16));
}

#ifdef LL_TC_EBPF
#include <linux/pkt_cls.h>

#define DP_REDIRECT TC_ACT_REDIRECT
#define DP_DROP     TC_ACT_SHOT
#define DP_PASS     TC_ACT_OK

#define DP_LLB_ISTAMP(md) (((struct __sk_buff *)md)->cb[3] = LLB_PIPE_ISTAMP_FLAG)
#define DP_LLB_OSTAMP(md) (((struct __sk_buff *)md)->cb[3] = LLB_PIPE_OSTAMP_FLAG)
#define DP_LLB_RST_STAMP(md) (((struct __sk_buff *)md)->cb[3] = 0)
#define DP_LLB_ISTAMPED(md) (((struct __sk_buff *)md)->cb[3] == LLB_PIPE_ISTAMP_FLAG)
#define DP_LLB_OSTAMPED(md) (((struct __sk_buff *)md)->cb[3] == LLB_PIPE_OSTAMP_FLAG)
#define DP_LLB_IS_EGR(md) ((((struct __sk_buff *)md)->ingress_ifindex) != (((struct __sk_buff *)md)->ifindex))
#define DP_LLB_INIFIDX_NONE(md) (((struct __sk_buff *)md)->ingress_ifindex == 0)
#define DP_LLB_EGRESS_HOOK(md) (DP_LLB_STAMPED(md) || DP_LLB_INIFIDX_NONE(md))
#define DP_NEED_MIRR(md) (((struct __sk_buff *)md)->cb[0] == LLB_MIRR_MARK)
#define DP_GET_MIRR(md) (((struct __sk_buff *)md)->cb[1])
#define DP_CTX_MIRR(md) (((struct __sk_buff *)md)->cb[0] == LLB_MIRR_MARK)
#define DP_IFI(md) (((struct __sk_buff *)md)->ifindex)
#define DP_IIFI(md) (((struct __sk_buff *)md)->ingress_ifindex)
#define DP_OIFI(md) (((struct __sk_buff *)md)->ifindex)
#define DP_PDATA(md) (((struct __sk_buff *)md)->data)
#define DP_PDATA_END(md) (((struct __sk_buff *)md)->data_end)
#define DP_MDATA(md) (((struct __sk_buff *)md)->data_meta)
#define DP_GET_LEN(md) (((struct __sk_buff *)md)->len)
#define DP_LLB_SET_CRC_HINT(md, crc) (((struct __sk_buff *)md)->priority = crc)
#define DP_LLB_SET_CRC_OFF(md, val) (((struct __sk_buff *)md)->mark = LLB_PIPE_CRC_DONE_FLAG | (val))

static void __always_inline
dp_llb_add_crc_off(void *md,  struct xfi *xf, int val)
{
  if (xf->pm.nfc) {
    struct __sk_buff *lsk = (struct __sk_buff *)md;
    __u16 off = lsk->mark >> 16;
    lsk->mark = (LLB_PIPE_CRC_DONE_FLAG | ((val)+off) << 16);
  }
}

#ifdef HAVE_CLANG13
#define DP_NEW_FCXF(xf)                  \
  int val = 0;                           \
  xf = bpf_map_lookup_elem(&xfis, &val); \
  if (!xf) {                             \
    return DP_DROP;                      \
  }                                      \
  memset(xf, 0, sizeof(*xf));            \

#else

#define DP_NEW_FCXF(xf)                  \
  struct xfi xfr;                        \
  memset(&xfr, 0, sizeof(xfr));          \
  xf = &xfr;                             \

#endif

#define TRACER_CALL(ctx, xf)             \
  if (xf->pm.pten) {                     \
    if (xf->pm.pten == DP_PTEN_ALL ||    \
       ((xf->pm.pten == DP_PTEN_TRAP) && \
        (xf->pm.pipe_act & LLB_PIPE_EXCP_MASK))) { \
      dp_ring_event(ctx, xf, 0);         \
    }                                    \
  }


#ifndef LLB_LAT_RESOLUTION
#define LLB_LAT_RESOLUTION (1000ULL)
#endif

#ifdef HAVE_DP_LAT

#define DP_SET_STARTS(xf) (xf)->fm.tstamp = bpf_ktime_get_ns()

#define RECPP_LATENCY(ctx, xf)           \
do {                                     \
  int idx;                               \
  __u64 diff_ns;                         \
  diff_ns = bpf_ktime_get_ns() -         \
     ((xf)->fm.tstamp);                  \
  idx = diff_ns/(LLB_LAT_RESOLUTION);    \
  if (idx >= LLB_PPLAT_MAP_ENTRIES) {    \
    idx = LLB_PPLAT_MAP_ENTRIES-1;       \
  }                                      \
  dp_do_map_stats(ctx, xf, LL_DP_PPLAT_MAP, idx); \
} while(0)
#else
#define DP_SET_STARTS(xf)
#define RECPP_LATENCY(ctx, xf)
#endif

#define RETURN_TO_MP_OUT(ctx)                    \
do {                                             \
  xf->pm.phit |= LLB_DP_RES_HIT;                 \
  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);\
  return DP_PASS;                                \
} while(0)

#define TCALL_CRC1() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID1)
#define TCALL_CRC2() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID2)

static int __always_inline
dp_ring_event(void *ctx,  struct xfi *xf, int cp)
{
  struct ll_dp_pmdi *pmd;
  int z = 0;
  __u64 flags = BPF_F_CURRENT_CPU;

  /* Metadata will be in the perf event before the packet data. */
  pmd = bpf_map_lookup_elem(&pkts, &z);
  if (!pmd) return 0;

  BPF_TRACE_PRINTK("[TRACE] Ring event --");

  pmd->ifindex = DP_IFI(ctx);
  pmd->phit = xf->pm.phit;
  pmd->dp_inport = xf->pm.iport;
  pmd->dp_oport = xf->pm.oport;
  pmd->table_id = xf->pm.table_id;
  pmd->rcode = xf->pm.rcode;
  pmd->pkt_len = DP_GET_LEN(ctx);
  if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IP)) {
    pmd->resolve_ip = xf->l34m.daddr[0];
    if (xf->pm.nf & LLB_NAT_DST) {
      pmd->resolve_ip = xf->nm.nxip4;
    } else if (xf->pm.nf & LLB_NAT_SRC) {
      pmd->resolve_ip = xf->nm.nrip4;
    }
  } else {
    pmd->resolve_ip = 0;
  }

  flags |= (__u64)pmd->pkt_len << 32;
  
  if (cp == 0) {
    if (bpf_perf_event_output(ctx, &pkt_ring, flags,
                            pmd, sizeof(*pmd))) {
      BPF_ERR_PRINTK("[TRACE] PKT ring event failed");
    }
  } else {
    if (bpf_perf_event_output(ctx, &cp_ring, flags,
                            pmd, sizeof(*pmd))) {
      BPF_ERR_PRINTK("[TRACE] CP ring event failed");
    }
  }
  return DP_DROP;
}

static int __always_inline
dp_csum_tcall(void *ctx,  struct xfi *xf)
{
  int z = 0;
  __u32 crc = 0xffffffff;
  __u32 pkt_len = DP_GET_LEN(ctx);

   /* Init state-variables */
  xf->km.skey[0] = 0;
  *(__u16 *)&xf->km.skey[2] = xf->pm.l4_off;
  *(__u16 *)&xf->km.skey[4] = xf->pm.l3_plen;
  *(__u32 *)&xf->km.skey[8] = crc;

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);
  bpf_skb_pull_data(ctx, pkt_len);

  TCALL_CRC1();
  return DP_PASS;
}

static int __always_inline
dp_sunp_tcall(void *ctx,  struct xfi *xf)
{
  int z = 0;

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);
  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_SUNP_PGM_ID2);

  return DP_PASS;
}

static int __always_inline
dp_pkt_is_l2mcbc(struct xfi *xf, void *md)
{
  struct __sk_buff *b = md;  

  if (b->pkt_type == PACKET_MULTICAST ||
      b->pkt_type == PACKET_BROADCAST) {
    return 1;
  }
  return 0;
}

static int __always_inline
dp_vlan_info(struct xfi *xf, void *md)
{
  struct __sk_buff *b = md;

  if (b->vlan_present) {
    /*xf->l2m.dl_type = bpf_htons((__u16)(b->vlan_proto));*/
    xf->l2m.vlan[0] = bpf_htons((__u16)(b->vlan_tci));
    return 1;
  }

  return 0;
}

static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_skb_change_head(md, delta, 0);
}

static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                        BPF_F_ADJ_ROOM_FIXED_GSO);
}

static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, delta, BPF_ADJ_ROOM_MAC,
                            flags);
}

static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                            flags);
}

static int __always_inline
dp_buf_add_room3(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, delta, BPF_ADJ_ROOM_NET,
                            flags);
}

static int __always_inline
dp_buf_delete_room3(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_NET, 
                            flags);
}

static int __always_inline
dp_redirect_port_in(void *tbl, struct xfi *xf)
{
  int *oif;
  int key = xf->pm.oport;

  oif = bpf_map_lookup_elem(tbl, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  return bpf_redirect(*oif, BPF_F_INGRESS);
}

static int __always_inline
dp_redirect_port(void *tbl, struct xfi *xf)
{
  int *oif;
  int key = xf->pm.oport;

  oif = bpf_map_lookup_elem(tbl, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  BPF_DBG_PRINTK("[REDR] port %d OIF %d", key, *oif);
  return bpf_redirect(*oif, 0);
}

static int __always_inline
dp_rewire_port(void *tbl, struct xfi *xf)
{
  int *oif;
  int key = xf->pm.oport;

  oif = bpf_map_lookup_elem(tbl, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  return bpf_redirect(*oif, BPF_F_INGRESS);
}

static int __always_inline
dp_populate_ppv2(void *md, struct xfi *xf, void *start, __be32 *csum)
{
  struct proxy_hdr_v2 *ppv2h;
  struct proxy_ipv4_hdr *piph;
  __u8 sig[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                   0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  ppv2h = start; 
  if (ppv2h + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  memcpy(ppv2h->sig, sig, 12);
  ppv2h->ver_cmd = 0x21;
  ppv2h->family = 0x11;
  ppv2h->len = bpf_htons(sizeof(struct proxy_ipv4_hdr));

  piph = (void *)(ppv2h + 1);
  if (piph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  piph->src_addr = xf->l34m.saddr[0];
  piph->dst_addr = xf->l34m.daddr[0];
  piph->src_port = xf->l34m.source;
  piph->dst_port = xf->l34m.dest;

  *csum = bpf_csum_diff((__be32 *)ppv2h, sizeof(*ppv2h) + sizeof(*piph), 0, 0, *csum);

  return 0;
}

static int __always_inline
dp_fixup_ppv2(void *md, struct xfi *xf)
{
  struct tcphdr *tcp;
  void *dend;
  __be32 oval = 0;
  __u32 nval = 0;
  __u32 csum = 0;

  if (xf->l2m.dl_type != bpf_htons(ETH_P_IP) || xf->l34m.nw_proto != IPPROTO_TCP) {
    return 0;
  }

  dend = DP_TC_PTR(DP_PDATA_END(md));
  tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if (tcp + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  if (xf->pm.oppv2) {
    oval = tcp->seq;
    nval = bpf_ntohl(tcp->seq) + sizeof(struct proxy_hdr_v2) + sizeof(struct proxy_ipv4_hdr);
    tcp->seq = bpf_htonl(nval);
    nval = tcp->seq;
  } else if (xf->pm.ippv2) {
    oval = tcp->ack_seq;
    nval = bpf_ntohl(tcp->ack_seq) - (sizeof(struct proxy_hdr_v2) + sizeof(struct proxy_ipv4_hdr));
    tcp->ack_seq = bpf_htonl(nval);
    nval = tcp->ack_seq;
  }

  csum = bpf_csum_diff((__be32 *)&nval, 4, (__be32 *)&oval, 4, tcp->check);
  tcp->check = csum_fold_helper_diff((__u32)csum);

  return 0;
}

static int __always_inline
dp_ins_ppv2(void *md, struct xfi *xf)
{ 
  struct proxy_hdr_v2 *ppv2h;
  struct iphdr *iph;
  struct tcphdr *tcp;
  struct tcphdr *ntcp;
  void *dend;
  __u16 doff;
  __u32 olp;
  __u32 nlp;
  __u64 flags;
  __u32 csum = 0;

  int len = sizeof(struct proxy_hdr_v2);

  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP) && xf->l34m.nw_proto == IPPROTO_TCP) {
    len += sizeof(struct proxy_ipv4_hdr);
  } else {
    // FIXME - not supported now
    return 0;
  }

  flags = BPF_F_ADJ_ROOM_FIXED_GSO;

  dp_llb_add_crc_off(md, xf, len);

  /* add room between mac and network header */
  if (dp_buf_add_room3(md, len, flags)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    dend = DP_TC_PTR(DP_PDATA_END(md));
    iph = DP_ADD_PTR(DP_PDATA(md), xf->pm.l3_off);
    if (iph + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    iph->tot_len = bpf_htons(xf->pm.l3_len + len);
    dp_ipv4_new_csum((void *)iph);

    dend = DP_TC_PTR(DP_PDATA_END(md));
    tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off + len);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    doff = tcp->doff << 2;

    /* Checksum changes due to TCP segment length change */
    olp = (__u32)bpf_htons(xf->pm.l3_plen);
    nlp = (__u32)bpf_htons(xf->pm.l3_plen + len);
    csum = bpf_csum_diff((__be32 *)&nlp, 4, (__be32 *)&olp, 4, tcp->check);


    ntcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
    if (ntcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    __builtin_memmove(ntcp, tcp, sizeof(*tcp));

    if (doff == 24) {
      __u8 *top =  (void *)(tcp + 1);
      if (top + 4 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      __u8 *ntop =  (void *)(ntcp + 1);
      if (ntop + 4 > dend) { 
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      memcpy(ntop, top, 4);
      ppv2h = (void *)(ntop + 4);
      dp_populate_ppv2(md, xf, ppv2h, &csum);
    } else if (doff == 28) {
      __u8 *top =  (void *)(tcp + 1);
      if (top + 8 > dend) { 
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      __u8 *ntop =  (void *)(ntcp + 1);
      if (ntop + 8 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      memcpy(ntop, top, 8);
      ppv2h = (void *)(ntop + 8);
      dp_populate_ppv2(md, xf, ppv2h, &csum);
    } else if (doff == 32) {
      __u8 *top =  (void *)(tcp + 1);
      if (top + 12 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      __u8 *ntop =  (void *)(ntcp + 1);
      if (ntop + 12 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      memcpy(ntop, top, 12);
      ppv2h = (void *)(ntop + 12);
      dp_populate_ppv2(md, xf, ppv2h, &csum);
    } else if (doff == 36) {
      __u8 *top =  (void *)(tcp + 1);
      if (top + 16 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      __u8 *ntop =  (void *)(ntcp + 1);
      if (ntop + 16 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      memcpy(ntop, top, 16);
      ppv2h = (void *)(ntop + 16);
      dp_populate_ppv2(md, xf, ppv2h, &csum);
    } else if (doff == 40) {
      __u8 *top =  (void *)(tcp + 1);
      if (top + 20 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      __u8 *ntop =  (void *)(ntcp + 1);
      if (ntop + 20 > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      memcpy(ntop, top, 20);
      ppv2h = (void *)(ntop + 20);
      dp_populate_ppv2(md, xf, ppv2h, &csum);
    } else if (doff != 20) {
      /* Max of 20 bytes of options */
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    dend = DP_TC_PTR(DP_PDATA_END(md));
    iph = DP_ADD_PTR(DP_PDATA(md), xf->pm.l3_off);
    if (iph + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    tcp->check = csum_fold_helper_diff((__u32)csum);
  }
  return 0;
}

static int __always_inline
dp_record_it(void *skb, struct xfi *xf)
{
  int *oif;
  int key = LLB_PORT_NO;

  oif = bpf_map_lookup_elem(&tx_intf_map, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  return bpf_clone_redirect(skb, *oif, 0); 
}

static int __always_inline
dp_remove_vlan_tag(void *ctx, struct xfi *xf)
{
  void *dend;
  struct ethhdr *eth;

  bpf_skb_vlan_pop(ctx);
  eth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (eth + 1 > dend) {
    return -1;
  }

  dp_llb_add_crc_off(ctx, xf, -((int)sizeof(struct vlanhdr)));

  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = xf->l2m.dl_type;

  return 0;
}

static int __always_inline
dp_insert_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;

  bpf_skb_vlan_push(ctx, bpf_ntohs(xf->l2m.dl_type), bpf_ntohs(vlan));
  eth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (eth + 1 > dend) {
    return -1;
  }

  dp_llb_add_crc_off(ctx, xf, sizeof(struct vlanhdr));

  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);

  return 0;
}

static int __always_inline
dp_swap_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  bpf_skb_vlan_pop(ctx);
  return dp_insert_vlan_tag(ctx, xf, vlan);
}

static int __always_inline
dp_set_tcp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
  __be32 *old_sip = xf->l34m.saddr;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(xf->l34m.saddr), 0);

  //DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

static int __always_inline
dp_set_tcp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR |sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);

  //xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
  __be32 *old_dip = xf->l34m.daddr;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(xf->l34m.saddr), 0);

  //DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

static int __always_inline
dp_set_tcp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  //xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_sport(void *md, struct xfi *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_sport_off = xf->pm.l4_off + offsetof(struct tcphdr, source);
  __be32 old_sport = xf->l34m.source;

  if (xf->l34m.frg || !xport) return 0;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_sport_off, &xport, sizeof(xport), 0);
 // xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_tcp_dport(void *md, struct xfi *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_dport_off = xf->pm.l4_off + offsetof(struct tcphdr, dest);
  __be32 old_dport = xf->l34m.dest;

  if (xf->l34m.frg) return 0;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_dport_off, &xport, sizeof(xport), 0);
  //xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_udp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
  __be32 *old_sip = xf->l34m.saddr;
  //__be16 csum = 0;

  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_sip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_sip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_sip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_sip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));

  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(xf->l34m.saddr), 0);
  //DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

static int __always_inline
dp_set_udp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  //__be16 csum = 0;
  __be32 old_sip = xf->l34m.saddr4;
  
  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR |sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
  __be32 *old_dip = xf->l34m.daddr;
  //__be16 csum = 0;

  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_dip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_dip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_dip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, udp_csum_off, old_dip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(xf->l34m.daddr), 0);
  //DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

static int __always_inline
dp_set_udp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;
  //__be16 csum = 0;
  
  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  //xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_sport(void *md, struct xfi *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_sport_off = xf->pm.l4_off + offsetof(struct udphdr, source);
  __be32 old_sport = xf->l34m.source;
  //__be16 csum = 0;

  if (xf->l34m.frg || !xport) return 0;

  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_sport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, udp_sport_off, &xport, sizeof(xport), 0);
  //xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_udp_dport(void *md, struct xfi *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_dport_off = xf->pm.l4_off + offsetof(struct udphdr, dest);
  __be32 old_dport = xf->l34m.dest;
  //__be16 csum = 0;

  if (xf->l34m.frg) return 0;

  /* UDP checksum = 0 is valid */
  //bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l4_csum_replace(md, udp_csum_off, old_dport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, udp_dport_off, &xport, sizeof(xport), 0);
  //xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_icmp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int icmp6_csum_off = xf->pm.l4_off + offsetof(struct icmp6hdr, icmp6_cksum);
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
  __be32 *old_sip = xf->l34m.saddr;
  __u32 csum = 0;
  __u16 icmp_csum = 0;

  bpf_skb_load_bytes(md, icmp6_csum_off, &icmp_csum, sizeof(icmp_csum));

  csum = bpf_csum_diff((__be32 *)xip, 16, (__be32 *)old_sip, 16, icmp_csum);
  icmp_csum = csum_fold_helper_diff((__u32)csum);

  bpf_skb_store_bytes(md, icmp6_csum_off, &icmp_csum, sizeof(icmp_csum), 0);
  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(struct in6_addr), 0);
  //DP_XADDR_CP(xf->l34m.saddr, xip);
 
  return 0;
}

static int __always_inline
dp_set_icmp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;
 
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  //xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_icmp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int icmp6_csum_off = xf->pm.l4_off + offsetof(struct icmp6hdr, icmp6_cksum);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
  __be32 *old_dip = xf->l34m.daddr;
  __u32 csum = 0;
  __u16 icmp_csum = 0;

  bpf_skb_load_bytes(md, icmp6_csum_off, &icmp_csum, sizeof(icmp_csum));
  
  csum = bpf_csum_diff((__be32 *)xip, 16, (__be32 *)old_dip, 16, icmp_csum);
  icmp_csum = csum_fold_helper_diff((__u32)csum);

  bpf_skb_store_bytes(md, icmp6_csum_off, &icmp_csum, sizeof(icmp_csum), 0);
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(struct in6_addr), 0);
  //DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

static int __always_inline
dp_set_icmp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;
  
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  //xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_sctp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);

  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(struct in6_addr), 0);
  //DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

static int __always_inline
dp_set_sctp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  int ip_len_off = xf->pm.l3_off + offsetof(struct iphdr, tot_len);
  __be32 old_sip = xf->l34m.saddr4;
  
  if (xf->pm.l3_adj) {
    __be32 old_len = bpf_htons(xf->pm.l3_len);
    __be32 new_len = bpf_htons(xf->pm.l3_len+xf->pm.l3_adj);
    bpf_l3_csum_replace(md, ip_csum_off, old_len, new_len, sizeof(__u16));
    bpf_skb_store_bytes(md, ip_len_off, &new_len, sizeof(__u16), 0);
    xf->pm.l3_plen += xf->pm.l3_adj;
    xf->pm.l3_len += xf->pm.l3_adj;
    xf->pm.l3_adj = 0;
  }
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  //xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_sctp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
 
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(struct in6_addr), 0);
  //DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

static int __always_inline
dp_set_sctp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  int ip_len_off = xf->pm.l3_off + offsetof(struct iphdr, tot_len);
  __be32 old_dip = xf->l34m.daddr4;

   if (xf->pm.l3_adj) {
    __be32 old_len = bpf_htons(xf->pm.l3_len);
    __be32 new_len = bpf_htons(xf->pm.l3_len+xf->pm.l3_adj);
    bpf_l3_csum_replace(md, ip_csum_off, old_len, new_len, sizeof(__u16));
    bpf_skb_store_bytes(md, ip_len_off, &new_len, sizeof(__u16), 0);
    xf->pm.l3_plen += xf->pm.l3_adj;
    xf->pm.l3_len += xf->pm.l3_adj;
    xf->pm.l3_adj = 0;
  }

  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  //xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_sctp_sport(void *md, struct xfi *xf, __be16 xport)
{
  uint32_t csum = 0;
  int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum);
  int sctp_sport_off = xf->pm.l4_off + offsetof(struct sctphdr, source);

  if (xf->l34m.frg || !xport) return 0;

  bpf_skb_store_bytes(md, sctp_csum_off, &csum , sizeof(csum), 0);
  bpf_skb_store_bytes(md, sctp_sport_off, &xport, sizeof(xport), 0);
  //xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_sctp_dport(void *md, struct xfi *xf, __be16 xport)
{
  uint32_t csum = 0;
  int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum); 
  int sctp_dport_off = xf->pm.l4_off + offsetof(struct sctphdr, dest);

  if (xf->l34m.frg) return 0;

  bpf_skb_store_bytes(md, sctp_csum_off, &csum , sizeof(csum), 0);
  bpf_skb_store_bytes(md, sctp_dport_off, &xport, sizeof(xport), 0);
  //xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_do_dnat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_tcp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_tcp_dst_ip(ctx, xf, xip);
    }
    dp_set_tcp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_udp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_udp_dst_ip(ctx, xf, xip);
    }
    dp_set_udp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_sctp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_sctp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_sctp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_sctp_dst_ip(ctx, xf, xip);
    }
    dp_set_sctp_dport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    if (!xf->nm.cdis) {
      dp_csum_tcall(ctx, xf);
    } else {
      DP_LLB_SET_CRC_OFF(ctx, 0);
    }
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    if (xf->nm.nrip4) {
      dp_set_icmp_src_ip(ctx, xf, xf->nm.nrip4);
    }
    dp_set_icmp_dst_ip(ctx, xf, xip);
  }

  return 0;
}

static int __always_inline
dp_do_dnat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_tcp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_tcp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    }
    dp_set_tcp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_udp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_udp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_udp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_udp_dst_ip6(ctx, xf, xip);
    }
    dp_set_udp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_sctp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_sctp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    }
    dp_set_sctp_dport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    if (!xf->nm.cdis) {
      dp_csum_tcall(ctx, xf);
    } else {
      DP_LLB_SET_CRC_OFF(ctx, 0);
    }
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6)  {
    if (!DP_XADDR_ISZR(xf->nm.nrip)) {
      dp_set_icmp_src_ip6(ctx, xf, xf->nm.nrip);
    }
    dp_set_icmp_dst_ip6(ctx, xf, xip);
  }

  return 0;
}

static int __always_inline
dp_do_snat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_tcp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_tcp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_tcp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_udp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_udp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_udp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_sctp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_sctp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_sctp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_sctp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_sctp_sport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    if (!xf->nm.cdis) {
      dp_csum_tcall(ctx, xf);
    } else {
      DP_LLB_SET_CRC_OFF(ctx, 0);
    }
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    dp_set_icmp_src_ip(ctx, xf, xip);
    if (xf->nm.nrip4) {
      dp_set_icmp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
  }

  return 0;
}

static int __always_inline
dp_do_snat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_tcp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_tcp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_tcp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_tcp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_udp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_udp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_udp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_udp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_udp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_sctp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_sctp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_sctp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_sctp_sport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    if (!xf->nm.cdis) {
      dp_csum_tcall(ctx, xf);
    } else {
      DP_LLB_SET_CRC_OFF(ctx, 0);
    }
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6)  {
    dp_set_icmp_src_ip6(ctx, xf, xip);
    if (!DP_XADDR_ISZR(xf->nm.nrip)) {
      dp_set_icmp_dst_ip6(ctx, xf, xf->nm.nrip);
    }
  }

  return 0;
}

static int __always_inline
dp_do_dnat64(void *md, struct xfi *xf)
{
  struct iphdr *iph;
  struct ethhdr *eth;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct vlanhdr *vlh;
  __be32 sum;
  void *dend;

  if (xf->l34m.nw_proto != IPPROTO_TCP &&
      xf->l34m.nw_proto != IPPROTO_UDP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Pre-conversion validation */
  void *orig_data = DP_TC_PTR(DP_PDATA(md));
  void *orig_data_end = DP_TC_PTR(DP_PDATA_END(md));
  __u32 orig_len = (__u32)(orig_data_end - orig_data);  
  
  /* Validate packet size before conversion */
  if (xf->pm.l3_len > 1500) {  /* Standard Ethernet MTU */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Validate IPv6 packet structure */
  if (xf->pm.l3_plen < 40) {  /* Minimum IPv6 header size */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Validate NAT64 address mappings */
  if (xf->nm.nrip4 == 0 || xf->nm.nxip4 == 0) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Check for invalid destination addresses */
  __u32 dst_addr_host = bpf_ntohl(xf->nm.nxip4);
  if ((dst_addr_host & 0xF0000000) == 0xE0000000 ||  /* Multicast */
      (dst_addr_host & 0xFF000000) == 0xFF000000) {   /* Broadcast */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Perform protocol conversion */
  if (bpf_skb_change_proto(md, bpf_htons(ETH_P_IP), 0) < 0) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PROTO_ERR);
    return -1;
  }
  
  /* Post-conversion validation */
  void *new_data = DP_TC_PTR(DP_PDATA(md));
  void *new_data_end = DP_TC_PTR(DP_PDATA_END(md));
  __u32 new_len = (__u32)(new_data_end - new_data);
  
  
  /* Validate packet structure after conversion */
  if (new_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PROTO_ERR);
    return -1;
  }
  
  /* Check for suspicious length changes that might indicate corruption */
  __s32 len_diff = new_len - orig_len;
  if (len_diff < -40 || len_diff > 40) {  /* IPv6 header (40) vs IPv4 header (20) = ±20 expected */
    BPF_TRACE_PRINTK("[TRACE-V6] Suspicious length change after conversion: %d->%d (diff=%d)", 
                     orig_len, new_len, len_diff);
    /* Don't fail immediately, but log for debugging */
  }  

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Enhanced packet integrity validation after protocol conversion */
  __u32 total_pkt_len = (__u32)(dend - (void*)eth);
  if (total_pkt_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }  

  xf->l2m.dl_type = bpf_htons(ETH_P_IP);
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  if (xf->l2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
    eth->h_proto = bpf_htons(0x8100);
    vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  } else {
    eth->h_proto = xf->l2m.dl_type;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  xf->pm.l3_len = xf->pm.l3_plen + sizeof(*iph);
  xf->pm.l3_off = DP_DIFF_PTR(iph, eth);
  xf->pm.l4_off = DP_DIFF_PTR((iph+1), eth);

  /* Outer IP header */
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = xf->l34m.nw_proto;
  iph->saddr    = xf->nm.nrip4;
  iph->daddr    = xf->nm.nxip4;
  
  /* Explicitly clear fields that may be corrupted by bpf_skb_change_proto */
  iph->id       = 0;      // Clear identification field
  iph->frag_off = 0;      // Clear fragment offset - prevents IPv6 address contamination
  iph->tos      = 0;      // Clear type of service field

  dp_ipv4_new_csum((void *)iph);
  
  /* Validate IPv4 header integrity after construction */
  if (iph->version != 4) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  if (iph->ihl != 5) {  /* Standard 20-byte header */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Validate IPv4 total length without storing in variable to satisfy verifier */
  __u16 tot_len_temp = bpf_ntohs(iph->tot_len);
  if (tot_len_temp < 20) {  /* Minimum IPv4 header size */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  if (tot_len_temp > 1500) {  /* Standard MTU */
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Use safe bounds checking that the verifier understands */
  /* Don't do arithmetic with total_len - use fixed offsets instead */
  if (iph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Validate L4 header bounds using fixed sizes */
  void *l4_hdr = (void *)(iph + 1);
  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    struct tcphdr *tcp_check = (struct tcphdr *)l4_hdr;
    if (tcp_check + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    struct udphdr *udp_check = (struct udphdr *)l4_hdr;
    if (udp_check + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
  }
  
  /* Check for fragmentation flags that might indicate corruption */
  __u16 frag_off = bpf_ntohs(iph->frag_off);
  if ((frag_off & 0x3FFF) != 0) {  /* Fragment offset should be 0 for new packets */    
    /* Fix the corruption by clearing fragment fields */
    iph->frag_off = 0;  /* Clear corrupted fragment offset */
    iph->id = 0;        /* Clear potentially corrupted ID field */
    
    /* Recalculate checksum after fixing corruption */
    dp_ipv4_new_csum((void *)iph);    
  }  

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    tcp = (void *)(iph + 1);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    sum = bpf_csum_diff(xf->l34m.saddr, sizeof(xf->l34m.saddr),
                &iph->saddr, sizeof(iph->saddr), 0);
    sum = bpf_csum_diff(xf->l34m.daddr, sizeof(xf->l34m.daddr),
                &iph->daddr, sizeof(iph->daddr), sum);

    bpf_l4_csum_replace(md, xf->pm.l4_off + offsetof(struct tcphdr, check),
                        0, sum, BPF_F_PSEUDO_HDR);

    dp_set_tcp_dport(md, xf, xf->nm.nxport);

  } else {

    udp = (void *)(iph + 1);
    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    dp_set_udp_dport(md, xf, xf->nm.nxport);
  }

  /* Final packet structure validation - avoid pkt_end arithmetic */
  void *final_data_end = DP_TC_PTR(DP_PDATA_END(md));
  
  /* Use safe bounds checking without arithmetic on pkt_end */
  if ((void*)eth + sizeof(struct ethhdr) + sizeof(struct iphdr) > final_data_end) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Check reasonable maximum size using fixed offset */
  if ((void*)eth + 1514 < final_data_end) {
    /* Packet is larger than max Ethernet frame - just log, don't fail */
    BPF_TRACE_PRINTK("[TRACE-V6] Final packet larger than standard Ethernet frame");
  }
  
  /* Verify IPv4 header is still valid after all modifications */
  if (iph + 1 > final_data_end) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  
  /* Verify L4 header is within bounds */
  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    struct tcphdr *final_tcp = (void *)(iph + 1);
    if (final_tcp + 1 > final_data_end) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    struct udphdr *final_udp = (void *)(iph + 1);
    if (final_udp + 1 > final_data_end) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
  }  
  
  /* Re-establish packet pointers for final logging to satisfy verifier */
  struct ethhdr *final_eth = DP_TC_PTR(DP_PDATA(md));
  void *final_dend = DP_TC_PTR(DP_PDATA_END(md));
  
  if (final_eth + 1 <= final_dend) {
    struct iphdr *final_iph = (void *)(final_eth + 1);
    if (final_iph + 1 <= final_dend) {
      BPF_TRACE_PRINTK("[TRACE-V6] Final IPv4: %x->%x proto=%d", 
                       bpf_ntohl(final_iph->saddr), bpf_ntohl(final_iph->daddr), final_iph->protocol);
    }
  }
  return 0;
}

static int __always_inline
dp_do_snat46(void *md, struct xfi *xf)
{
  struct ipv6hdr *ip6h;
  struct ethhdr *eth;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct vlanhdr *vlh;
  __be32 sum;
  void *dend;

  if (xf->l34m.nw_proto != IPPROTO_TCP &&
      xf->l34m.nw_proto != IPPROTO_UDP) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PROTO_ERR);
    return -1;
  }

  if (bpf_skb_change_proto(md, bpf_htons(ETH_P_IPV6), 0) < 0) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PROTO_ERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  xf->l2m.dl_type = bpf_htons(ETH_P_IPV6);
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  if (xf->l2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
    eth->h_proto = bpf_htons(0x8100);
    vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  } else {
    eth->h_proto = xf->l2m.dl_type;
  }

  ip6h = (void *)(eth + 1);
  if (ip6h + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  xf->pm.l3_len = xf->pm.l3_plen + sizeof(*ip6h);
  xf->pm.l3_off = DP_DIFF_PTR(ip6h, eth);
  xf->pm.l4_off = DP_DIFF_PTR((ip6h+1), eth);

  /* Outer IP header */
  ip6h->version  = 6;
  ip6h->payload_len = bpf_htons(xf->pm.l3_plen);
  ip6h->hop_limit = 64; // FIXME - Copy inner ??
  ip6h->flow_lbl[0] = 0;
  ip6h->flow_lbl[1] = 0;
  ip6h->flow_lbl[2] = 0;
  ip6h->nexthdr = xf->l34m.nw_proto;
  memcpy(&ip6h->saddr, xf->nm.nxip, 16);
  memcpy(&ip6h->daddr, xf->nm.nrip, 16);

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    tcp = (void *)(ip6h + 1);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    sum = bpf_csum_diff(&xf->l34m.saddr[0], 4,
                        (void *)&ip6h->saddr, sizeof(ip6h->saddr), 0);
    sum = bpf_csum_diff(&xf->l34m.daddr[0], 4,
                        (void *)&ip6h->daddr, sizeof(ip6h->daddr), sum);
    bpf_l4_csum_replace(md, xf->pm.l4_off + offsetof(struct tcphdr, check),
                      0, sum, BPF_F_PSEUDO_HDR);

    dp_set_tcp_sport(md, xf, xf->nm.nxport);

  } else {

    udp = (void *)(ip6h + 1);
    if (udp + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    dp_set_udp_sport(md, xf, xf->nm.nxport);
  }

  return 0;
}

static void __always_inline
dp_set_qmap(void *md, __u32 qnum)
{
  ((struct __sk_buff *)md)->queue_mapping = qnum;
}

static __u32 __always_inline
dp_get_qmap(void *md)
{
  return ((struct __sk_buff *)md)->queue_mapping;
}

static void __always_inline
dp_reset_pkt_hash(void *md)
{
  bpf_set_hash_invalid(md);
}

static __u32 __always_inline
dp_get_pkt_hash(void *md)
{
  __u32 hash = 0;
  bpf_set_hash_invalid(md);
  hash = bpf_get_hash_recalc(md);
  return hash;
}

static __u32 __always_inline
dp_get_tun_hash(struct xfi *xf)
{
  __u32 hash = ((xf->tm.tunnel_id  >> 16) & 0xffff) ^
                (xf->tm.tunnel_id & 0xffff);
  return hash;
}

static int __always_inline
dp_pktbuf_read(void *md, __u32 off, void *tobuf, __u32 tolen)
{
  return bpf_skb_load_bytes(md, off, tobuf, tolen);
}

static int __always_inline
dp_pktbuf_write(void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)
{
  return bpf_skb_store_bytes(md, off, frmbuf, frmlen, flags);
}

static int __always_inline
dp_pktbuf_expand_tail(void *md, __u32 len)
{
  return bpf_skb_change_tail(md, len, 0);
}

#else /* XDP utilities */

#define DP_LLB_ISTAMP(md)
#define DP_LLB_OSTAMP(md)
#define DP_LLB_RST_STAMP(md)
#define DP_LLB_ISTAMPED(md) (0)
#define DP_LLB_OSTAMPED(md) (0)
#define DP_LLB_EGRESS_HOOK(md) (0)
#define DP_LLB_INIFIDX_NONE(md) (0)
#define DP_LLB_IS_EGR(md) (0)
#define DP_NEED_MIRR(md) (0)
#define DP_GET_MIRR(md)  (0)
#define DP_REDIRECT XDP_REDIRECT
#define DP_DROP     XDP_DROP
#define DP_PASS     XDP_PASS
#define DP_LLB_SET_CRC_HINT(md, crc)
#define DP_LLB_SET_CRC_OFF(md, val)

static void __always_inline
dp_llb_add_crc_off(void *md,  struct xfi *xf, int val)
{
  return;
}

#define dp_sunp_tcall(x, y)
#define TCALL_CRC1()
#define TCALL_CRC2()
#define RETURN_TO_MP_OUT(x)
#define TRACER_CALL(ctx, xf)
#define RECPP_LATENCY(ctx, xf)
#define DP_SET_STARTS(xf)

static int __always_inline
dp_pkt_is_l2mcbc(struct xfi *xf, void *md)
{
  if (xf->l2m.dl_dst[0] & 1) {
    return 1;
  }

  if (xf->l2m.dl_dst[0] == 0xff &&
      xf->l2m.dl_dst[1] == 0xff &&
      xf->l2m.dl_dst[2] == 0xff &&
      xf->l2m.dl_dst[3] == 0xff &&
      xf->l2m.dl_dst[4] == 0xff &&
      xf->l2m.dl_dst[5] == 0xff) {
    return 1;
  }

  return 0;
}

static int __always_inline
dp_ring_event(void *ctx,  struct xfi *xf, int cp)
{
  return 0;
}
 
static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, -delta);
}

static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, delta);
}

static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, -delta);
}

static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, delta);
}

static int __always_inline
dp_buf_add_room3(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, -delta);
}

static int __always_inline
dp_buf_delete_room3(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, delta);
}

static int __always_inline
dp_redirect_port_in(void *tbl, struct xfi *xf)
{
  return 0;
}

static int __always_inline
dp_redirect_port(void *tbl, struct xfi *xf)
{
  return bpf_redirect_map(tbl, xf->pm.oport, 0);
}

static int __always_inline
dp_rewire_port(void *tbl, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

static int __always_inline
dp_record_it(void *ctx, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

static int __always_inline
dp_fixup_ppv2(void *md, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

static int __always_inline
dp_ins_ppv2(void *md, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

#define DP_IFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_IIFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_OIFI(md) (0)
#define DP_PDATA(md) (((struct xdp_md *)md)->data)
#define DP_PDATA_END(md) (((struct xdp_md *)md)->data_end)
#define DP_MDATA(md) (((struct xdp_md *)md)->data_meta)
#define DP_GET_LEN(md)  ((((struct xdp_md *)md)->data_end) - \
                         (((struct xdp_md *)md)->data)) \

static int __always_inline
dp_remove_vlan_tag(void *ctx, struct xfi *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;
  struct vlanhdr *vlh;

  if (start + (sizeof(*eth) + sizeof(*vlh)) > dend) {
    return -1;
  }
  eth = DP_ADD_PTR(DP_PDATA(ctx), (int)sizeof(struct vlanhdr));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = xf->l2m.dl_type;
  if (dp_remove_l2(ctx, (int)sizeof(struct vlanhdr))) {
    return -1;
  }
  return 0;
}

static int __always_inline
dp_insert_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  struct ethhdr *neth;
  struct vlanhdr *vlh;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (dp_add_l2(ctx, (int)sizeof(struct vlanhdr))) {
    return -1;
  }

  neth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));

  /* Revalidate for satisfy eBPF verifier */
  if (DP_TC_PTR(neth) + sizeof(*neth) > dend) {
    return -1;
  }

  memcpy(neth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(neth->h_source, xf->l2m.dl_src, 6);

  /* FIXME : */
  neth->h_proto = bpf_htons(ETH_P_8021Q);

  vlh = DP_ADD_PTR(DP_PDATA(ctx), sizeof(*neth));

  if (DP_TC_PTR(vlh) + sizeof(*vlh) > dend) {
    return -1;
  }

  vlh->h_vlan_TCI = vlan;
  /* FIXME : */
  vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  return 0;
}

static int __always_inline
dp_swap_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  struct ethhdr *eth;
  struct vlanhdr *vlh;
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if ((start +  sizeof(*eth)) > dend) {
    return -1;
  }
  eth = DP_TC_PTR(DP_PDATA(ctx));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);

  vlh = DP_ADD_PTR(DP_PDATA(ctx), sizeof(*eth));
  if (DP_TC_PTR(vlh) + sizeof(*vlh) > dend) {
    return -1;
  }
  vlh->h_vlan_TCI = vlan;
  return 0;
}

static int __always_inline
dp_do_snat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

static int __always_inline
dp_do_snat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

static int __always_inline
dp_do_dnat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

static int __always_inline
dp_do_dnat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

static int __always_inline
dp_do_dnat64(void *ctx, struct xfi *xf)
{
  /* FIXME - TBD */
  return 0;
}

static int __always_inline
dp_do_snat46(void *ctx, struct xfi *xf)
{
  /* FIXME - TBD */
  return 0;
}

static void __always_inline
dp_set_qmap(void *md, __u32 qnum)
{
  /* FIXME - TODO */
  return;
}

static __u32 __always_inline
dp_get_qmap(void *md)
{
  /* FIXME - TODO */
  return 0;
}

static void __always_inline
dp_reset_pkt_hash(void *md)
{
  /* FIXME - TODO */
  return;
}

static __u32 __always_inline
dp_get_pkt_hash(void *md)
{
  /* FIXME - TODO */
  return 0;
}

static __u32 __always_inline
dp_get_tun_hash(struct xfi *xf)
{
  /* FIXME - TODO */
  return 0;
}

static int __always_inline
dp_pktbuf_read(void *md, __u32 off, void *buf, __u32 tolen)
{
  /* FIXME - TODO */
  return -1;
}

static int __always_inline
dp_pktbuf_write(void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)
{
  /* FIXME - TODO */
  return -1;
}

static int __always_inline
dp_pktbuf_expand_tail(void *md, __u32 len)
{
  /* FIXME - TODO */
  return -1;
}

#endif  /* End of XDP utilities */

static int __always_inline
dp_do_out_vlan(void *ctx, struct xfi *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;
  int vlan;

  vlan = xf->pm.bd;

  if (vlan == 0) {
    /* Strip existing vlan. Nothing to do if there was no vlan tag */
    if (xf->l2m.vlan[0] != 0) {
      if (dp_remove_vlan_tag(ctx, xf) != 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
    } else {
      if (start + sizeof(*eth) > dend) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
      eth = DP_TC_PTR(DP_PDATA(ctx));
      memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
      memcpy(eth->h_source, xf->l2m.dl_src, 6);
    }
    return 0;
  } else {
    /* If existing vlan tag was present just replace vlan-id, else 
     * push a new vlan tag and set the vlan-id
     */
    eth = DP_TC_PTR(DP_PDATA(ctx));
    if (xf->l2m.vlan[0] != 0) {
      if (dp_swap_vlan_tag(ctx, xf, vlan) != 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
    } else {
      if (dp_insert_vlan_tag(ctx, xf, vlan) != 0) {
        LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
        return -1;
      }
    }
  }

  return 0;
}

static int __always_inline
dp_pop_outer_l2_metadata(void *md, struct xfi *xf)
{
  memcpy(&xf->l2m.dl_type, &xf->il2m.dl_type, 
         sizeof(xf->l2m) - sizeof(xf->l2m.vlan));

  memcpy(xf->pm.lkup_dmac, xf->il2m.dl_dst, 6);
  xf->il2m.valid = 0;

  return 0;
}

static int __always_inline
dp_pop_outer_metadata(void *md, struct xfi *xf, int l2tun)
{
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));

  xf->pm.tcp_flags = xf->pm.itcp_flags;
  xf->pm.l4fin = xf->pm.il4fin;
  xf->pm.l3_off = xf->pm.il3_off;
  xf->pm.l3_len = xf->pm.il3_len;
  xf->pm.l3_plen = xf->pm.il3_plen;
  xf->pm.l4_off = xf->pm.il4_off;
  xf->il34m.valid = 0;
  xf->tm.tun_decap = 1;

  if (l2tun) {
    return dp_pop_outer_l2_metadata(md, xf);  
  }

  return 0;
}

static int __always_inline
dp_do_strip_ipip(void *md, struct xfi *xf)
{
  struct ethhdr *eth;
  void *dend;
  int olen = sizeof(struct iphdr);

  if (dp_buf_delete_room(md, olen, BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    BPF_ERR_PRINTK("[IPIP] Failed to delete room");
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  dp_llb_add_crc_off(md, xf, -olen);

  /* Recreate eth header */
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  eth->h_proto = xf->l2m.dl_type;

  /* We do not care about vlan's now
   * After routing it will be set as per outgoing BD
   */
  xf->l2m.vlan[0] = 0;
  xf->l2m.vlan[1] = 0;

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

static int __always_inline
dp_do_ins_ipip(void *md,
               struct xfi *xf,
               __be32 rip,
               __be32 sip,
               __be32 tid,
               int skip_md) 
{
  void *dend;
  struct ethhdr *eth;
  struct iphdr *iph;
  int olen;
  __u64 flags;

  olen  = sizeof(*iph);

  flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4; 

  /* add room between mac and network header */
  if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  dp_llb_add_crc_off(md, xf, olen);

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_IPIP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  xf->tm.tun_encap = 1;

  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = 0;
  xf->l34m.dest = 0;
  xf->pm.l4_off = xf->pm.l3_off + sizeof(*iph);
  
  return 0;
}

static int __always_inline
dp_do_strip_vxlan(void *md, struct xfi *xf, int olen)
{
  struct ethhdr *eth;
  struct vlanhdr *vlh;
  void *dend;

  if (dp_buf_delete_room(md, olen, BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    BPF_ERR_PRINTK("[VXLAN] Failed to remove header");
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }
  memcpy(eth->h_dest, xf->il2m.dl_dst, 2*6);
  if (xf->il2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
    vlh->h_vlan_encapsulated_proto = xf->il2m.dl_type;
  } else {
    eth->h_proto = xf->il2m.dl_type;
  }

  dp_llb_add_crc_off(md, xf, -olen);

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(&xf->l2m, &xf->il2m, sizeof(xf->l2m));

  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

static int __always_inline
dp_do_ins_vxlan(void *md,
                struct xfi *xf,
                __be32 rip,
                __be32 sip,
                __be32 tid,
                int skip_md) 
{
  void *dend;
  struct ethhdr *eth;
  struct ethhdr *ieth;
  struct iphdr *iph;
  struct udphdr *udp;
  struct vxlanhdr *vx;
  int olen, l2_len;
  __u64 flags;

  /* We do not pass vlan header inside vxlan */
  if (xf->l2m.vlan[0] != 0) {
    if (dp_remove_vlan_tag(md, xf) < 0) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }
  }

  olen   = sizeof(*iph)  + sizeof(*udp) + sizeof(*vx); 
  l2_len = sizeof(*eth);

  flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
          BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
          BPF_F_ADJ_ROOM_ENCAP_L2(l2_len);
  olen += l2_len;

  dp_llb_add_crc_off(md, xf, olen);

  /* add room between mac and network header */
  if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

#if 0
  /* 
   * FIXME - Inner ethernet 
   * No need to copy but if we dont 
   * inner eth header is sometimes not set
   * properly especially when incoming packet
   * was vlan tagged
   */
  if (xf->l2m.vlan[0]) {
    memcpy(eth->h_dest, xf->il2m.dl_dst, 2*6);
    eth->h_proto = xf->il2m.dl_type;
  }
#endif

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_UDP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  udp = (void *)(iph + 1);
  if (udp + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Outer UDP header */
  udp->source = xf->l34m.source + VXLAN_OUDP_SPORT;
  udp->dest   = bpf_htons(VXLAN_OUDP_DPORT);
  udp->check  = 0;
  udp->len    = bpf_htons(xf->pm.l3_len +  olen - sizeof(*iph));

  /* VxLAN header */
  vx = (void *)(udp + 1);
  if (vx + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Control agent should pass tunnel-id something like this -
   * bpf_htonl(((__le32)(tid) << 8) & 0xffffff00);
   */
  vx->vx_vni   = tid;
  vx->vx_flags = VXLAN_VI_FLAG_ON;

  /* Inner eth header -
   * XXX If we do not copy, inner eth is zero'd out
   */
  ieth = (void *)(vx + 1);
  if (ieth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  memcpy(ieth->h_dest, xf->il2m.dl_dst, 2*6);
  ieth->h_proto = xf->il2m.dl_type;

  /* Tunnel metadata */
  xf->tm.tun_type  = LLB_TUN_VXLAN;
  xf->tm.tunnel_id = bpf_ntohl(tid);
  xf->pm.tun_off   = sizeof(*eth) + 
                    sizeof(*iph) + 
                    sizeof(*udp) +
                    sizeof(*vx);
  xf->tm.tun_encap = 1;

  /* Reset flags essential for L2 header rewrite */
  xf->l2m.vlan[0] = 0;
  xf->l2m.dl_type = bpf_htons(ETH_P_IP);


  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));
  memcpy(&xf->il2m, &xf->l2m, sizeof(xf->l2m));
  xf->il2m.vlan[0] = 0;

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;
  xf->pm.l3_off = sizeof(*eth);
  xf->pm.l4_off = sizeof(*eth) + sizeof(*iph);

  return 0;
}

static int __always_inline
dp_do_strip_gtp(void *md, struct xfi *xf, int olen)
{
  struct ethhdr *eth;
  void *dend;

  if (olen < sizeof(*eth)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  if (dp_buf_delete_room(md, olen - sizeof(*eth), BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    BPF_ERR_PRINTK("[GTP] Failed to remove hdr");
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Recreate eth header */
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  eth->h_proto = xf->l2m.dl_type;

  /* We do not care about vlan's now
   * After routing it will be set as per outgoing BD
   */
  xf->l2m.vlan[0] = 0;
  xf->l2m.vlan[1] = 0;

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

static int __always_inline
dp_do_ins_gtp(void *md,
              struct xfi *xf,
              __be32 rip,
              __be32 sip,
              __be32 tid,
              __u8 qfi,
              int skip_md) 
{
  void *dend;
  struct gtp_v1_hdr *gh;
  struct gtp_v1_ehdr *geh;
  struct gtp_dl_pdu_sess_hdr *gedh;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct udphdr *udp;
  int olen;
  __u64 flags;
  int ghlen;
  __u8 espn;

  if (qfi) {
    ghlen = sizeof(*gh) + sizeof(*geh) + sizeof(*gedh);
    espn = GTP_EXT_FM;
  } else {
    ghlen = sizeof(*gh);
    espn = 0;
  }

  olen   = sizeof(*iph)  + sizeof(*udp) + ghlen;

  flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
          BPF_F_ADJ_ROOM_ENCAP_L4_UDP;

  /* add room between mac and network header */
  if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_UDP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  udp = (void *)(iph + 1);
  if (udp + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  /* Outer UDP header */
  udp->source = bpf_htons(GTPU_UDP_SPORT);
  udp->dest   = bpf_htons(GTPU_UDP_DPORT);
  udp->check  = 0;
  udp->len    = bpf_htons(xf->pm.l3_len +  olen - sizeof(*iph));

  /* GTP header */
  gh = (void *)(udp + 1);
  if (gh + 1 > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  gh->ver = GTP_VER_1;
  gh->pt = 1;
  gh->espn = espn;
  gh->teid = tid;
  gh->mt = GTP_MT_TPDU;
  gh->mlen = bpf_ntohs(xf->pm.l3_len + ghlen);
  
  if (qfi) {
    /* GTP extension header */
    geh = (void *)(gh + 1);
    if (geh + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    geh->seq = 0;
    geh->npdu = 0;
    geh->next_hdr = GTP_NH_PDU_SESS;

    gedh = (void *)(geh + 1);
    if (gedh + 1 > dend) {
      LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
      return -1;
    }

    gedh->cmn.len = 1;
    gedh->cmn.pdu_type = GTP_PDU_SESS_DL;
    gedh->qfi = qfi;
    gedh->ppp = 0;
    gedh->rqi = 0;
    gedh->next_hdr = 0;
  }
  /* Tunnel metadata */
  xf->tm.tun_type  = LLB_TUN_GTP;
  xf->tm.tunnel_id = bpf_ntohl(tid);
  xf->pm.tun_off   = sizeof(*eth) + 
                    sizeof(*iph) + 
                    sizeof(*udp) +
                    sizeof(*gh);
  xf->tm.tun_encap = 1;

  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));
  xf->il2m.vlan[0] = 0;

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;
  xf->pm.l4_off = xf->pm.l3_off + sizeof(*iph);
  
  return 0;
}


static int __always_inline
xdp2tc_has_xmd(void *md, struct xfi *xf)
{
  void *data      = DP_TC_PTR(DP_PDATA(md));
  void *data_meta = DP_TC_PTR(DP_MDATA(md));
  struct ll_xmdi *meta = data_meta;

  /* Check XDP gave us some data_meta */
  if (meta + 1 <= data) {
    if (meta->pi.skip != 0) {
      xf->pm.tc = 0;
      LLBS_PPLN_PASSC(xf, 0);
      return 1;
    }

    if (meta->pi.iport) {
      xf->pm.oport = meta->pi.iport;
      LLBS_PPLN_REWIRE(xf);
    } else {
      xf->pm.oport = meta->pi.oport;
      LLBS_PPLN_RDR(xf);
    }
    xf->pm.tc = 0;
    meta->pi.skip = 1;
    return 1;
  }

  return 0;
}

static int __always_inline
dp_tail_call(void *ctx,  struct xfi *xf, void *fa, __u32 idx)
{
  int z = 0;

  if (xf->nm.ct_sts != 0) {
    return DP_PASS;
  }

#ifdef HAVE_DP_FC
  /* fa state can be reused */ 
  bpf_map_update_elem(&fcas, &z, fa, BPF_ANY);
#endif

  /* xfi state can be reused */ 
  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);

  bpf_tail_call(ctx, &pgm_tbl, idx);

  return DP_PASS;
}

static int __always_inline
dp_swap_mac_header(void *ctx, struct xfi *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;

  if (start + sizeof(*eth) > dend) {
    LLBS_PPLN_DROPC(xf, LLB_PIPE_RC_PLERR);
    return -1;
  }

  eth = DP_TC_PTR(start);
  memcpy(eth->h_dest, xf->l2m.dl_src, 6);
  memcpy(eth->h_source, xf->l2m.dl_dst, 6);
  return 0;
}

static int __always_inline
dp_set_llb_mac_header(void *ctx)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;

  if (start + sizeof(*eth) > dend) {
    return -1;
  }

  eth = DP_TC_PTR(start);
  eth->h_dest[0] = 0x00;
  eth->h_dest[1] = 0x00;
  eth->h_dest[2] = 0xca;
  eth->h_dest[3] = 0xfe;
  eth->h_dest[4] = 0xfa;
  eth->h_dest[5] = 0xce;
  return 0;
}

#endif
