/*
 * loxilb_libdp.c: LoxiLB DP config library 
 * Copyright (C) 2022,  NetLOX <www.netlox.io>
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "bpf.h"
#include "libbpf.h"

#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

#include "loxilb_libdp.h"
#include "llb_kern_mon.h"
#include "loxilb_libdp.skel.h"
#include "../common/pdi.h"
#include "../common/common_frame.h"
#include "../common/sockproxy.h"

#ifndef PATH_MAX
#define PATH_MAX  4096
#endif

typedef struct llb_dp_sect {
#define SECNAMSIZ 64
  char name[SECNAMSIZ];
  int valid;
  int ref;
  int (*setup)(struct bpf_object *obj);
} llb_dp_sect_t;

typedef struct llb_bpf_mnt_ {
  struct bpf_object *obj;
  int mp_type;
} llb_bpf_mnt_t;
 
typedef struct llb_dp_link {
  char ifname[IFNAMSIZ];
  struct bpf_object *obj; 
#define MAX_MPS (3)
  int nm;
  llb_bpf_mnt_t mp[MAX_MPS];
  int valid;
} llb_dp_link_t;
  
typedef struct llb_dp_map {
  int map_fd;  
  char *map_name;
  uint32_t max_entries;
  int has_pb;
  int pb_xtid;
  struct dp_pbc_stats *pbs;
  int has_pol;
  struct dp_pol_stats *pls;
  pthread_rwlock_t stat_lock;
} llb_dp_map_t;

typedef struct llb_dp_struct
{
  pthread_rwlock_t lock;
  pthread_rwlock_t mplock;
  const char *ll_dp_fname;
  const char *ll_tc_fname;
  const char *ll_dp_dfl_sec;
  const char *ll_dp_pdir;
  pthread_t pkt_thr;
  pthread_t cp_thr;
  pthread_t mon_thr;
  int mgmt_ch_fd;
  int have_mtrace;
  int have_ptrace;
  int have_loader;
  int have_sockrwr;
  int have_sockmap;
  int have_noebpf;
  struct llb_kern_mon *monp;
  const char *cgroup_dfl_path;
  int cgfd;
  int smfd;
  int egr_hooks;
  int nodenum;
  llb_dp_map_t maps[LL_DP_MAX_MAP];
  llb_dp_link_t links[LLB_INTERFACES];
  llb_dp_sect_t psecs[LLB_PSECS];
  struct pdi_map *ufw4;
  struct pdi_map *ufw6;
  FILE *logfp;
  struct throttler cpt;
  uint64_t lctts;
  uint64_t lfcts;
} llb_dp_struct_t;

#define XH_LOCK()    pthread_rwlock_wrlock(&xh->lock)
#define XH_RD_LOCK() pthread_rwlock_rdlock(&xh->lock)
#define XH_UNLOCK()  pthread_rwlock_unlock(&xh->lock)

#define XH_MPLOCK()  pthread_rwlock_wrlock(&xh->mplock)
#define XH_MPUNLOCK() pthread_rwlock_unlock(&xh->mplock)

#define XH_BPF_OBJ() xh->links[0].obj

llb_dp_struct_t *xh;
static uint64_t lost;

static inline unsigned int
bpf_num_possible_cpus(void)
{
  int possible_cpus = libbpf_num_possible_cpus();
  if (possible_cpus < 0) {
    return 0;
  }
  return possible_cpus;
}

static inline unsigned int
bpf_num_online_cpus(void)
{
  int online_cpus = libbpf_num_online_cpus();
  if (online_cpus < 0) {
    return 0;
  }
  return online_cpus;
}

static void
ll_pretty_hex(void *ptr, int len)
{
  int i= 0, idx = 0;
  unsigned char tmp_buf[64] = { 0 };

  for (i = 0; i < len; i++) {
    idx += snprintf((void *)(tmp_buf + idx), 3, "%02x",
                    *((unsigned char *)ptr + i));

    if (idx >= 32) {
      printf("0x%s\r\n", tmp_buf);
      memset(tmp_buf, 0, 32);
      idx = 0;
    }
  }

  if (idx) {
    printf("0x%s\r\n", tmp_buf);
  }

  return;
}

static int
libbpf_print_fn(enum libbpf_print_level level, 
                const char *format,
                va_list args)
{
  /* Ignore debug-level libbpf logs */
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

static void
llb_decode_pmdata(char *buf, struct ll_dp_pmdi *pmd)
{
  int n = 0;
  if (pmd->phit) {
    n += sprintf(buf + n, "phit:");
    if (pmd->phit &  LLB_DP_FC_HIT) {
      n += sprintf(buf + n, "fc,");
    }
    if (pmd->phit &  LLB_DP_IF_HIT) {
      n += sprintf(buf + n, "if,");
    }
    if (pmd->phit &  LLB_DP_TMAC_HIT) {
      n += sprintf(buf + n, "tmac,");
    }
    if (pmd->phit &  LLB_DP_CTM_HIT) {
      n += sprintf(buf + n, "ct,");
    }
    if (pmd->phit &  LLB_DP_RT_HIT) {
      n += sprintf(buf + n, "rt,");
    }
    if (pmd->phit &  LLB_DP_SESS_HIT) {
      n += sprintf(buf + n, "ses,");
    }
        if (pmd->phit &  LLB_DP_FW_HIT) {
      n += sprintf(buf + n, "fw,");
    }
    if (pmd->phit &  LLB_DP_CTSI_HIT) {
      n += sprintf(buf + n, "cti,");
    }
    if (pmd->phit &  LLB_DP_CTSO_HIT) {
      n += sprintf(buf + n, "cto,");
    }
    if (pmd->phit &  LLB_DP_NAT_HIT) {
      n += sprintf(buf + n, "nat,");
    }
    if (pmd->phit &  LLB_DP_CSUM_HIT) {
      n += sprintf(buf + n, "csum,");
    }
    if (pmd->phit &  LLB_DP_UNPS_HIT) {
      n += sprintf(buf + n, "unps,");
    }
    if (pmd->phit &  LLB_DP_NEIGH_HIT) {
      n += sprintf(buf + n, "nh,");
    }
    if (pmd->phit &  LLB_DP_DMAC_HIT) {
      n += sprintf(buf + n, "dm,");
    }
    if (pmd->phit &  LLB_DP_SMAC_HIT) {
      n += sprintf(buf + n, "sm,");
    }
    if (pmd->phit &  LLB_DP_RES_HIT) {
      n += sprintf(buf + n, "res,");
    }
    n += sprintf(buf + n, "** ");
  }

  if (pmd->rcode) {
     n += sprintf(buf + n, "rcode:");
    if (pmd->rcode & LLB_PIPE_RC_PARSER) {
      n += sprintf(buf + n, "parser,");
    }
    if (pmd->rcode & LLB_PIPE_RC_ACL_TRAP) {
      n += sprintf(buf + n, "acl-trap,");
    }
    if (pmd->rcode & LLB_PIPE_RC_RT_TRAP) {
      n += sprintf(buf + n, "rt-trap,");
    }
    if (pmd->rcode & LLB_PIPE_RC_TUN_DECAP) {
      n += sprintf(buf + n, "tun-decap,");
    }
    if (pmd->rcode & LLB_PIPE_RC_TUN_DECAP) {
      n += sprintf(buf + n, "tun-decap,");
    }
    if (pmd->rcode & LLB_PIPE_RC_FW_RDR) {
      n += sprintf(buf + n, "fw-rdr,");
    }
    if (pmd->rcode & LLB_PIPE_RC_FW_DRP) {
      n += sprintf(buf + n, "fw-drp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_UNPS_DRP) {
      n += sprintf(buf + n, "unps-drp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_CSUM_DRP) {
      n += sprintf(buf + n, "csum-drp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_UNX_DRP) {
      n += sprintf(buf + n, "unx-drp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_FCTO) {
      n += sprintf(buf + n, "fc-to,");
    }
    if (pmd->rcode & LLB_PIPE_RC_FCBP) {
      n += sprintf(buf + n, "fc-break,");
    }
    if (pmd->rcode & LLB_PIPE_RC_PLERR) {
      n += sprintf(buf + n, "plen-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_PROTO_ERR) {
      n += sprintf(buf + n, "proto-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_PLCT_ERR) {
      n += sprintf(buf + n, "ct-plen-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_ACT_DROP) {
      n += sprintf(buf + n, "adrop,");
    }
    if (pmd->rcode & LLB_PIPE_RC_ACT_UNK) {
      n += sprintf(buf + n, "aunk,");
    }
    if (pmd->rcode & LLB_PIPE_RC_TCALL_ERR) {
      n += sprintf(buf + n, "tcall-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_ACT_TRAP) {
      n += sprintf(buf + n, "atrap,");
    }
    if (pmd->rcode & LLB_PIPE_RC_PLRT_ERR) {
      n += sprintf(buf + n, "rt-plen-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_PLCS_ERR) {
      n += sprintf(buf + n, "csum-plen-err,");
    }
    if (pmd->rcode & LLB_PIPE_RC_BCMC) {
      n += sprintf(buf + n, "bcmc,");
    }
    if (pmd->rcode & LLB_PIPE_RC_POL_DRP) {
      n += sprintf(buf + n, "policer-drop,");
    }
    if (pmd->rcode & LLB_PIPE_RC_NOSMAC) {
      n += sprintf(buf + n, "smac-excp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_NODMAC) {
      n += sprintf(buf + n, "dmac-excp,");
    }
    if (pmd->rcode & LLB_PIPE_RC_NH_UNK) {
      n += sprintf(buf + n, "nh-excp,");
    }
  }
}

void __attribute__((weak))
goLinuxArpResolver(unsigned int destIP)
{
}

static void
llb_handle_pkt_tracer_event(void *ctx,
             int cpu,
             void *data,
             unsigned int data_sz)
{
  struct ll_dp_pmdi *pmd = data;
  struct tm *tm;
  char *pif;
  time_t t;
  char ts[32];
  char ifname[IFNAMSIZ];
  char pmdecode[1024];

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);
  llb_decode_pmdata(pmdecode, pmd);

  pif = if_indextoname(pmd->ifindex, ifname);

  printf("%-8s %-4s:%-4d ifi:%-4d(%s) iport:%-3d oport:%-3d tbl:%-2d %s\n", ts, "PKT", 
       pmd->pkt_len, pmd->ifindex, pif?:"", pmd->dp_inport, pmd->dp_oport, pmd->table_id, pmdecode);

  ll_pretty_hex(pmd->data, pmd->pkt_len > 64 ? 64: pmd->pkt_len);
}

static void *
llb_trace_proc_main(void *arg)
{
  struct perf_buffer *pb = arg;

  while (1) {
    perf_buffer__poll(pb, 100 /* timeout, ms */);
  } 

  /* NOT REACHED */
  return NULL;
}

static int
ll_fcmap_ent_set_flush(int tid, void *k, void *ita)
{
  return 1;
}

static void
ll_flush_fcmap(void)
{
  dp_map_ita_t it;
  struct dp_fcv4_key next_key;
  struct dp_fc_tacts *fc_val;
  uint64_t ns = get_os_nsecs();

  fc_val = calloc(1, sizeof(*fc_val));
  if (!fc_val) return;

  memset(&next_key, 0, sizeof(next_key));
  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = fc_val;
  it.uarg = &ns;

  XH_LOCK();
  llb_map_loop_and_delete(LL_DP_FCV4_MAP, ll_fcmap_ent_set_flush, &it);
  XH_UNLOCK();
  if (fc_val) free(fc_val);
}

int
llb_packet_trace_en(int en)
{
  void *key = NULL;
  int ifm_fd = xh->maps[LL_DP_INTF_MAP].map_fd;
  struct intf_key nkey;
  struct dp_intf_tact l2a;
  void *next_key = &nkey;

  if (xh->have_noebpf) {
    return 0;
  }

  if (en < 0 || en > 2) {
    return -1;
  }

  while (bpf_map_get_next_key(ifm_fd, &key, &next_key) == 0) {

    if (bpf_map_lookup_elem(ifm_fd, &next_key, &l2a) != 0) {
      goto next;
    }

    switch (en) {
    case 2:
      l2a.set_ifi.pten = 2;
      break;
    case 1:
      l2a.set_ifi.pten = 1;
      break;
    case 0:
      l2a.set_ifi.pten = 0;
      break;
    }

    bpf_map_update_elem(ifm_fd, &next_key, &l2a, BPF_ANY);
next:
    key = next_key;
  }

  ll_flush_fcmap();

  return 0;
}

int
llb_setup_pkt_ring(void)
{
  struct perf_buffer *pb = NULL;
  struct perf_buffer_opts pb_opts = { .sz = sizeof(struct perf_buffer_opts) } ;
  int pkt_fd = xh->maps[LL_DP_PKT_PERF_RING].map_fd;

  if (pkt_fd < 0) return -1;

  pb = perf_buffer__new(pkt_fd, 8 /* 32KB per CPU */,
          llb_handle_pkt_tracer_event, NULL, NULL, &pb_opts);
  if (libbpf_get_error(pb)) {
    fprintf(stderr, "Failed to create perf buffer\n");
    goto cleanup;
  }

  pthread_create(&xh->pkt_thr, NULL, llb_trace_proc_main, pb);

  return 0;

cleanup:
  perf_buffer__free(pb);
  return -1;
}

static void
llb_handle_cp_event(void *ctx,
             int cpu,
             void *data,
             unsigned int data_sz)
{
  struct ll_dp_pmdi *pmd = data;

  if (do_throttle(&xh->cpt)) {
    return;
  }

  if (pmd->rcode & LLB_PIPE_RC_RESOLVE) {
    goLinuxArpResolver(pmd->resolve_ip);
    return;
  }
}

static void *
llb_cp_proc_main(void *arg)
{
  struct perf_buffer *pb = arg;

  while (1) {
    perf_buffer__poll(pb, 100 /* timeout, ms */);
  }

  /* NOT REACHED */
  return NULL;
}

int
llb_setup_cp_ring(void)
{
  struct perf_buffer *pb = NULL;
  struct perf_buffer_opts pb_opts = { .sz = sizeof(struct perf_buffer_opts) } ;
  int pkt_fd = xh->maps[LL_DP_CP_PERF_RING].map_fd;

  if (pkt_fd < 0) return -1;

  pb = perf_buffer__new(pkt_fd, 1 /* 4KB per CPU */, llb_handle_cp_event, NULL, NULL, &pb_opts);
  if (libbpf_get_error(pb)) {
    fprintf(stderr, "Failed to create cp-ring perf buffer\n");
    goto cleanup;
  }

  pthread_create(&xh->cp_thr, NULL, llb_cp_proc_main, pb);

  return 0;

cleanup:
  perf_buffer__free(pb);
  return -1;
}

#ifdef HAVE_DP_CT_SYNC

void __attribute__((weak))
goMapNotiHandler(struct ll_dp_map_notif *mn)
{
}

static void
llb_maptrace_lost(void *ctx, int cpu, __u64 cnt)
{
  XH_LOCK();
  lost += cnt;
  XH_UNLOCK();
}

static void
llb_maptrace_output(void *ctx, int cpu, void *data, __u32 size)
{
  struct map_update_data *map_data = (struct map_update_data*)data;
  struct ll_dp_map_notif noti;

  memset(&noti, 0, sizeof(noti));
  if (map_data->updater == UPDATER_KERNEL) {
    noti.addop = 1;
  } else if (map_data->updater == DELETE_KERNEL) {
    noti.addop = 0;
  } else return;
  noti.key = map_data->key;
  noti.key_len = map_data->key_size;

  noti.val = map_data->value;
  noti.val_len = map_data->value_size;

  goMapNotiHandler(&noti);
}

static void
llb_maptrace_uhook(int tid, int addop,
                   void *key, int key_sz,
                   void *val, int val_sz)
{
  map_update_data ud;

  if (!xh->have_mtrace) {
    return;
  }

  if (tid != LL_DP_CT_MAP) {
    return;
  }

  memset(&ud, 0, sizeof(ud));
  strcpy(ud.name, "ct_map");
  ud.updater = DELETE_KERNEL;
  if (key_sz) {
    memcpy(ud.key, key, key_sz > MAX_KEY_SIZE ? MAX_KEY_SIZE:key_sz); 
  }
  ud.key_size = key_sz;

  if (val_sz) {
    memcpy(ud.value, val, val_sz > MAX_VALUE_SIZE ? MAX_VALUE_SIZE:val_sz); 
  }
  ud.value_size = val_sz;
  llb_maptrace_output(NULL, 0, &ud, sizeof(ud));
}

static void *
llb_maptrace_main(void *arg)
{
  struct perf_buffer *pb = arg;

  while (1) {
    perf_buffer__poll(pb, 100 /* timeout, ms */);
  }

  /* NOT REACHED */
  return NULL;
}

static int
llb_setup_kern_sock(const char *cgroup_path)
{
  struct bpf_map *map;
  struct bpf_object *bpf_obj;
  struct bpf_program *prog;
  int cgfd = -1;
  int pfd;

  if (xh->have_noebpf) {
    return 0;
  }

  if (xh->cgfd <= 0) {
    cgfd = cgroup_create_get(cgroup_path);
    if (cgfd < 0) {
      goto err;
    }

    if (cgroup_join(cgroup_path)) {
      goto err;
    }
  } else {
    cgfd = xh->cgfd;
  }


  bpf_obj = bpf_object__open_file(LLB_SOCK_ADDR_IMG_BPF, NULL);
  if (!bpf_obj) {
    log_error("sockaddr: failed to open BPF object");
    goto err;
  }

  prog = bpf_object__next_program(bpf_obj, NULL);
  if (!prog) {
    log_error("sockaddr: no BPF program found in object");
    bpf_object__close(bpf_obj);
    goto err;
  }

  bpf_program__set_type(prog, BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
  bpf_program__set_expected_attach_type(prog, BPF_CGROUP_INET4_CONNECT);
  bpf_program__set_flags(prog, BPF_F_TEST_RND_HI32);

  if (bpf_object__load(bpf_obj)) {
    log_error("sockaddr: failed to load BPF object");
    bpf_object__close(bpf_obj);
    goto err;
  }

  pfd = bpf_program__fd(prog);
  if (pfd < 0) {
    log_error("sockaddr: failed to get program fd");
    bpf_object__close(bpf_obj);
    goto err;
  }

  if (bpf_prog_attach(pfd, cgfd, BPF_CGROUP_INET4_CONNECT,
            BPF_F_ALLOW_OVERRIDE)) {
    log_error("sockaddr: attach failed");
    goto err;
  }

  map = bpf_object__find_map_by_name(bpf_obj, "sock_rwr_map");
  if (!map) {
    goto err;
  }

  int map_fd = bpf_map__fd(map);
  if (map_fd < 0) {
    log_error("sock_rwr_map get failed");
    goto err1;
  }

  xh->maps[LL_DP_SOCK_RWR_MAP].map_fd = map_fd;
  if (xh->cgfd <= 0) {
    xh->cgfd = cgfd;
  }

  log_info("loxilb kern-sock attached (%d)", map_fd);
  return 0;
err1:
  bpf_prog_detach(cgfd, BPF_CGROUP_INET4_CONNECT);
err:
  close(cgfd);
  return -1;
}

static void
llb_unload_kern_sock(void)
{
  if (xh->cgfd > 0) {
    bpf_prog_detach(xh->cgfd, BPF_CGROUP_INET4_CONNECT);
    log_debug("deattached sock-addr");
    close(xh->cgfd);
  }
}

static int
llb_setup_kern_mon(void)
{
  struct llb_kern_mon *prog;
  int err;

  if (xh->have_noebpf) {
    return 0;
  }

  // Open and load eBPF Program
  prog = llb_kern_mon__open();
  if (!prog) {
      log_error("Failed to open and load BPF skeleton");
      return 1;
  }
  err = llb_kern_mon__load(prog);
  if (err) {
      log_error("Failed to load and verify BPF skeleton");
      goto cleanup;
  }

  // Attach the various kProbes
  err = llb_kern_mon__attach(prog);
  if (err) {
      log_error("Failed to attach BPF skeleton");
      goto cleanup;
  }

  xh->monp = prog;

  // Setup Perf buffer to process events from kernel
  struct perf_buffer_opts pb_opts = { .sz = sizeof(struct perf_buffer_opts) } ;

  struct perf_buffer *pb;
  pb = perf_buffer__new(bpf_map__fd(prog->maps.map_events), 16384,
            llb_maptrace_output, llb_maptrace_lost, NULL, &pb_opts);
  err = libbpf_get_error(pb);
  if (err) {
    log_error("failed to setup perf_buffer: %d", err);
    goto cleanup;
  }

  pthread_create(&xh->mon_thr, NULL, llb_maptrace_main, pb);

  return 0;

cleanup:
  llb_kern_mon__destroy(prog);
  return err < 0 ? -err : 0;

}

static void
llb_unload_kern_mon(void)
{
  if (xh->have_mtrace) {
    llb_kern_mon__detach(xh->monp);
    llb_kern_mon__destroy(xh->monp);
  }
}

#else

static void
llb_maptrace_uhook(int tid, int addop,
                   void *key, int key_sz,
                   void *val, int val_sz)
{
  return;
}

static int
llb_setup_kern_mon(void)
{
  return 0;
}

static void
llb_unload_kern_mon(void)
{
}

#endif

static void
llb_unload_kern_sockmap(void)
{
  if (xh->have_sockmap) {
    if (xh->smfd > 0) {
#ifdef HAVE_SOCKMAP_SKMSG
      bpf_prog_detach(xh->smfd, BPF_SK_MSG_VERDICT);
#else
      bpf_prog_detach(xh->smfd, BPF_SK_SKB_STREAM_VERDICT);
      bpf_prog_detach(xh->smfd, BPF_SK_SKB_STREAM_PARSER);
#endif
      log_debug("deattached sockmap");
    }
    if (xh->cgfd > 0) {
      bpf_prog_detach(xh->cgfd, BPF_CGROUP_SOCK_OPS);
      log_debug("deattached sockops");
    }
  }
}

#ifdef HAVE_SOCKMAP_SKMSG
static int
llb_setup_kern_sockmap_skmsg_helper(int map_fd)
{
  struct bpf_program *prog;
  struct bpf_map *map2;
  struct bpf_object *bpf_obj2;
  int pfd2;

  if (xh->have_noebpf) {
    return 0;
  }

  bpf_obj2 = bpf_object__open(LLB_SOCK_DIR_IMG_BPF);
  map2 = bpf_object__find_map_by_name(bpf_obj2, "sock_proxy_map");
  if (map2 == NULL) {
    log_error("sockdir: find map failed");
    goto err;
  }

  if (bpf_map__reuse_fd(map2, map_fd)) {
    log_error("sockdir: reusefd failed");
    goto err;
  }

  if (bpf_object__load(bpf_obj2)) {
    log_error("sockdir: obj load failed");
    goto err;
  }

  map_fd = bpf_map__fd(map2);
  if (map_fd < 0) {
    log_error("sockdir: map get failed");
    goto err;
  }

#if 0
  if (bpf_prog_load(LLB_SOCK_DIR_IMG_BPF, BPF_PROG_TYPE_SK_MSG, &bpf_obj2, &pfd2)) {
    log_error("sockdir: load failed");
    goto err;
  }
#endif

  bpf_object__for_each_program(prog, bpf_obj2) {
    pfd2 = bpf_program__fd(prog);
    if (bpf_prog_attach(pfd2, map_fd, BPF_SK_MSG_VERDICT, 0)) {
      log_error("sockdir: failed to attach\n");
      goto err1;
    }
  }
  return map_fd;

err1:
  bpf_object__for_each_program(prog, bpf_obj2) {
    pfd2 = bpf_program__fd(prog);
    bpf_prog_detach(map_fd, BPF_SK_MSG_VERDICT);
  }
err:
  return -1;
}

#else

static int
llb_setup_kern_sockmap_strparser_helper(int sockmap_fd)
{
  struct bpf_program *prog;
  struct bpf_map *map2;
  struct bpf_object *bpf_obj2;
  int map_fd;
  int pfd2;

  if (xh->have_noebpf) {
    return 0;
  }

  bpf_obj2 = bpf_object__open(LLB_SOCK_SP_IMG_BPF);
#ifdef HAVE_SOCKOPS
  map2 = bpf_object__find_map_by_name(bpf_obj2, "sock_proxy_map");
#else
  map2 = bpf_object__find_map_by_name(bpf_obj2, "sock_proxy_map2");
#endif
  if (map2 == NULL) {
    log_error("sockstream: find map failed");
    goto err;
  }

#ifdef HAVE_SOCKOPS
  if (bpf_map__reuse_fd(map2, sockmap_fd)) {
    log_error("sockdir: reusefd failed");
    goto err;
  }
#endif

  if (bpf_object__load(bpf_obj2)) {
    log_error("sockstream: obj load failed");
    goto err;
  }

  map_fd = bpf_map__fd(map2);
  if (map_fd < 0) {
    log_error("sockstream: map get failed");
    goto err;
  }

#if 0
  if (bpf_prog_load(LLB_SOCK_DIR_IMG_BPF, BPF_PROG_TYPE_SK_MSG, &bpf_obj2, &pfd2)) {
    log_error("sockdir: load failed");
    goto err;
  }
#endif

  bpf_object__for_each_program(prog, bpf_obj2) {
    pfd2 = bpf_program__fd(prog);
    if (!strcmp(bpf_program__name(prog), "llb_sock_parser")) {
      if (bpf_prog_attach(pfd2, map_fd, BPF_SK_SKB_STREAM_PARSER, 0)) {
        log_error("sockstream: failed to attach stream parser pgm\n");
        goto err1;
      }
    } else if (!strcmp(bpf_program__name(prog), "llb_sock_verdict")) {
      if (bpf_prog_attach(pfd2, map_fd, BPF_SK_SKB_STREAM_VERDICT, 0)) {
        log_error("sockstream: failed to attach stream verdict pgm\n");
        goto err1;
      }
    }
  }
  return map_fd;

err1:
  bpf_object__for_each_program(prog, bpf_obj2) {
    if (!strcmp(bpf_program__name(prog), "llb_sock_parser")) {
      bpf_prog_detach(map_fd, BPF_SK_SKB_STREAM_PARSER);
    } else if (!strcmp(bpf_program__name(prog), "llb_sock_verdict")) {
      bpf_prog_detach(map_fd, BPF_SK_SKB_STREAM_VERDICT);
    }
  }
err:
  return -1;
}
#endif

static int
llb_sockmap_op(struct llb_sockmap_key *key, int fd, int doadd)
{
  if (xh->have_noebpf) {
    return 0;
  }

  if (xh->smfd <= 0) {
    assert(0);
  }

  //log_debug("sockstream: dip 0x%lx sip 0x%lx\n", key->dip, key->sip);
  //log_debug("sockstream: dport 0x%lx sport 0x%lx\n", key->dport, key->sport);

  if (doadd) {
    return bpf_map_update_elem(xh->smfd, key, &fd, BPF_ANY);
  } else {
    return bpf_map_delete_elem(xh->smfd, key);
  }
}

static int
llb_setup_kern_sockmap(const char *cgroup_path)
{
#ifdef HAVE_SOCKOPS
  struct bpf_map *map;
  struct bpf_object *bpf_obj;
  int pfd;
#endif
  int cgfd = -1;
  int map_fd = -1;
  int map_fd2 = -1;

  if (xh->have_noebpf) {
    return 0;
  }

#ifdef HAVE_SOCKOPS 
  if (xh->cgfd <= 0) {
    cgfd = cgroup_create_get(cgroup_path);
    if (cgfd < 0) {
      goto err;
    }

    if (cgroup_join(cgroup_path)) {
      goto err;
    }

    if (bpf_prog_load(LLB_SOCK_MAP_IMG_BPF, BPF_PROG_TYPE_SOCK_OPS, &bpf_obj, &pfd)) {
      log_error("sockmap: load failed");
      goto err;
    }

  } else {
    cgfd = xh->cgfd;
  }

  if (bpf_prog_attach(pfd, cgfd, BPF_CGROUP_SOCK_OPS, 0)) {
    log_error("sockmap: attach failed");
    goto err;
  }

  map = bpf_object__find_map_by_name(bpf_obj, "sock_proxy_map");
  if (!map) {
    goto err;
  }

  map_fd = bpf_map__fd(map);
  if (map_fd < 0) {
    log_error("sock_proxy_map get failed\n");
    goto err1;
  }
#endif

#ifdef HAVE_SOCKMAP_SKMSG
  map_fd2 = llb_setup_kern_sockmap_skmsg_helper(map_fd);
  if (map_fd2 < 0) {
    log_error("sockmap: skmsg helper load failed");
    goto err1;
  }
#else
  map_fd2 = llb_setup_kern_sockmap_strparser_helper(map_fd);
  if (map_fd2 < 0) {
    log_error("sockmap: skstream helper load failed");
    goto err1;
  }
#endif

  xh->maps[LL_DP_SOCK_PROXY_MAP].map_fd = map_fd2;
  if (xh->cgfd <= 0) {
    xh->cgfd = cgfd;
  }
  xh->smfd = map_fd2;

  log_info("loxilb kern-sock-map attached (%d)", map_fd2);
  return 0;
err1:
  bpf_prog_detach(cgfd, BPF_CGROUP_SOCK_OPS);
#ifdef HAVE_SOCKOPS
err:
#endif
  if (xh->have_sockrwr == 0 && cgfd > 0) {
    close(cgfd);
  }
  return -1;
}

static int 
llb_objmap2fd(struct bpf_object *bpf_obj,
              const char *mapname)
{
  struct bpf_map *map;
  int map_fd = -1;
  char path[512];

  if (bpf_obj == NULL) {
    union bpf_attr attr;

    snprintf(path, 512, "%s/%s", xh->ll_dp_pdir, mapname);
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (__u64) (unsigned long)&path[0];
    map_fd = syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));

  } else {
    map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (!map) {
      goto out;
    }

    map_fd = bpf_map__fd(map);
  }
  log_trace("%s: %d", mapname, map_fd);
out:
  return map_fd;
}

static void
llb_setup_crc32c_map(int mapfd)
{
  int i;
  uint32_t crc;

  // Generate crc32c table
  for (i = 0; i < 256; i++) {
    crc = i;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ 0x82f63b78 : crc >> 1;
    bpf_map_update_elem(mapfd, &i, &crc, BPF_ANY);
  }
}

static void
llb_setup_ctctr_map(int mapfd)
{
  uint32_t k = 0;
  struct dp_ct_ctrtact ctr;

  memset(&ctr, 0, sizeof(ctr));
  ctr.start = (LLB_CT_MAP_ENTRIES/LLB_MAX_LB_NODES) * xh->nodenum;
  ctr.counter = ctr.start;
  ctr.entries = ctr.start + (LLB_CT_MAP_ENTRIES/LLB_MAX_LB_NODES);
  bpf_map_update_elem(mapfd, &k, &ctr, BPF_ANY);
}

static void
llb_setup_cpu_map(int mapfd)
{
  uint32_t qsz = 2048;
  unsigned int live_cpus = bpf_num_possible_cpus();
  int ret, i;

  for (i = 0; i < live_cpus && i < MAX_REAL_CPUS; i++) {
    ret = bpf_map_update_elem(mapfd, &i, &qsz, BPF_ANY);
    if (ret < 0) {
      log_error("Failed to update cpu-map %d ent", i);
    }
  }
}

static void
llb_setup_lcpu_map(int mapfd)
{
  unsigned int live_cpus = bpf_num_online_cpus();
  int ret, i;

  if (live_cpus > MAX_REAL_CPUS) {
    live_cpus = MAX_REAL_CPUS;
  }

  i = 0;
  ret = bpf_map_update_elem(mapfd, &i, &live_cpus, BPF_ANY);
  if (ret < 0) {
    log_error("Failed to update live cpu-map %d ent", i);
    assert(0);
  }
}

static int
llb_dflt_sec_map2fd_all(struct bpf_object *bpf_obj)
{
  int i = 0;
  int fd;
  int bfd;
  int err;
  int key = 0;
  struct bpf_program *prog;
  const char *section;

  for (; i < LL_DP_MAX_MAP; i++) {
    if (i == LL_DP_SOCK_RWR_MAP || i == LL_DP_SOCK_PROXY_MAP) continue;
    fd = llb_objmap2fd(bpf_obj, xh->maps[i].map_name);  
    if (fd < 0) {
      log_error("BPF: map2fd failed %s", xh->maps[i].map_name);
      continue;
    }
    xh->maps[i].map_fd = fd;

    if (!xh->have_loader) continue;

    if (i == LL_DP_PGM_MAP) {
      bpf_object__for_each_program(prog, bpf_obj) {
        bfd = bpf_program__fd(prog);

        section = bpf_program__section_name(prog);
        if (strcmp(section, "tc_packet_hook0") == 0) {
          key = 0;
        } else if (strcmp(section, "tc_packet_hook1") == 0) {
          key = 1;
        } else  if (strcmp(section, "tc_packet_hook2") == 0) {
          key = 2;
        } else  if (strcmp(section, "tc_packet_hook3") == 0) {
          key = 3;
        } else  if (strcmp(section, "tc_packet_hook4") == 0) {
          key = 4;
        } else  if (strcmp(section, "tc_packet_hook5") == 0) {
          key = 5;
        } else  if (strcmp(section, "tc_packet_hook6") == 0) {
          key = 6;
        } else  if (strcmp(section, "tc_packet_hook7") == 0) {
          key = 7;
        } else key = -1;
        if (key >= 0) {
          bpf_map_update_elem(fd, &key, &bfd, BPF_ANY);
        }
      }
    } else if (i == LL_DP_CRC32C_MAP) {
      llb_setup_crc32c_map(fd);
    } else if (i == LL_DP_CTCTR_MAP) {
      llb_setup_ctctr_map(fd);
    } else if (i == LL_DP_CPU_MAP) {
      //struct bpf_map *cpu_map = bpf_object__find_map_by_name(bpf_obj,
      //                                            xh->maps[i].map_name);
      //if (bpf_map__set_max_entries(cpu_map, libbpf_num_possible_cpus()) < 0) {
      //  log_warn("Failed to set max entries for cpu_map map: %s", strerror(errno));
      //}
      llb_setup_cpu_map(fd);
    } else if (i == LL_DP_LCPU_MAP) {
      //struct bpf_map *cpu_map = bpf_object__find_map_by_name(bpf_obj,
      //                                            xh->maps[i].map_name);
      //if (bpf_map__set_max_entries(cpu_map, libbpf_num_online_cpus()) < 0) {
      //  log_warn("Failed to set max entries for live_cpu_map map: %s", strerror(errno));
      //}
      llb_setup_lcpu_map(fd);
    } else if (i == LL_DP_CP_PERF_RING) {
      llb_setup_cp_ring();
    }
  }

  if (!xh->have_loader) {
    return 0;
  }

  /* Clean previous pins */
  if (bpf_object__unpin_maps(bpf_obj, xh->ll_dp_pdir) != 0) {
    log_warn("%s: Unpin maps failed", xh->ll_dp_pdir);
  }

  /* This will pin all maps in our bpf_object */
  err = bpf_object__pin_maps(bpf_obj, xh->ll_dp_pdir);
  if (err) {
    log_error("bpf: object pin failed");
    //assert(0);
  }

  return 0;
}

int
llb_dp_maps_attach(llb_dp_struct_t *xh)
{
  return llb_dflt_sec_map2fd_all(NULL);
}

static int
llb_set_dev_up(char *ifname, bool up)
{
  struct ifreq ifr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_ifindex = if_nametoindex(ifname);

  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }
  if (up && !(ifr.ifr_flags & IFF_UP)) {
    ifr.ifr_flags |= IFF_UP;
  } else if (!up && ifr.ifr_flags & IFF_UP) {
    ifr.ifr_flags &= ~IFF_UP;
  } else {
    close(fd);
    return 0;
  }

  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

static int
llb_set_dev_hw_ether(char *ifname, uint8_t *mac)
{
  struct ifreq ifr;
  int fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_ifindex = if_nametoindex(ifname);
  memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

  if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}



static int
llb_loader_init(llb_dp_struct_t *xh)
{
  int fd;
  int ret;
  struct ifreq ifr;
  char *dev = "/dev/net/tun";
  uint8_t mac[6] = { 0x00, 0x00, 0xca, 0xfe, 0xfa, 0xce };
  
  if ((fd = open(dev, O_RDWR)) < 0 ) {
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  
  strncpy(ifr.ifr_name, LLB_MGMT_CHANNEL, IFNAMSIZ);
  
  if ((ret = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return ret;
  }

  if ((ret = ioctl(fd, TUNSETPERSIST, 1)) < 0) {
    close(fd);
    return ret;
  }

  xh->mgmt_ch_fd = fd;
  llb_set_dev_up(LLB_MGMT_CHANNEL, 1);
  llb_set_dev_hw_ether(LLB_MGMT_CHANNEL, mac);

  /* First unload eBPF/XDP */
  llb_dp_link_attach(LLB_MGMT_CHANNEL, XDP_LL_SEC_DEFAULT,
                     LL_BPF_MOUNT_XDP, 1);

  llb_dp_link_attach(LLB_MGMT_CHANNEL, TC_LL_SEC_DEFAULT,
                     LL_BPF_MOUNT_TC, 1);

  /* Now load eBPF/XDP */
  ret = llb_dp_link_attach(LLB_MGMT_CHANNEL, XDP_LL_SEC_DEFAULT,
                           LL_BPF_MOUNT_XDP, 0);
  if (ret != 0 ) {
    close(fd);
    return ret;
  }

  ret = llb_dp_link_attach(LLB_MGMT_CHANNEL, TC_LL_SEC_DEFAULT,
                           LL_BPF_MOUNT_TC, 0);

  if (ret != 0 ) {
    close(fd);
    return ret;
  }

  return 0;
}

static void
llb_xh_init(llb_dp_struct_t *xh)
{
  xh->ll_dp_fname = LLB_FP_IMG_DEFAULT;
  xh->ll_tc_fname = LLB_FP_IMG_BPF;
  xh->ll_dp_dfl_sec = XDP_LL_SEC_DEFAULT;
  xh->ll_dp_pdir  = LLB_DB_MAP_PDIR;

  xh->maps[LL_DP_INTF_MAP].map_name = "intf_map";
  xh->maps[LL_DP_INTF_MAP].has_pb   = 0;
  xh->maps[LL_DP_INTF_MAP].max_entries   = LLB_INTF_MAP_ENTRIES;

  xh->maps[LL_DP_INTF_STATS_MAP].map_name = "intf_stats_map";
  xh->maps[LL_DP_INTF_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_INTF_STATS_MAP].max_entries = LLB_INTERFACES; 
  xh->maps[LL_DP_INTF_STATS_MAP].pbs = calloc(LLB_INTERFACES, 
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_BD_STATS_MAP].map_name = "bd_stats_map";
  xh->maps[LL_DP_BD_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_BD_STATS_MAP].max_entries = LLB_INTF_MAP_ENTRIES;
  xh->maps[LL_DP_BD_STATS_MAP].pbs = calloc(LLB_INTF_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_SMAC_MAP].map_name = "smac_map";
  xh->maps[LL_DP_SMAC_MAP].has_pb   = 0;
  xh->maps[LL_DP_SMAC_MAP].max_entries   = LLB_SMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TMAC_MAP].map_name = "tmac_map";
  xh->maps[LL_DP_TMAC_MAP].has_pb   = 1;
  xh->maps[LL_DP_TMAC_MAP].pb_xtid  = LL_DP_TMAC_STATS_MAP;
  xh->maps[LL_DP_TMAC_MAP].max_entries   = LLB_TMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TMAC_STATS_MAP].map_name = "tmac_stats_map";
  xh->maps[LL_DP_TMAC_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TMAC_STATS_MAP].max_entries = LLB_TMAC_MAP_ENTRIES;
  xh->maps[LL_DP_TMAC_STATS_MAP].pbs = calloc(LLB_TMAC_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_CT_MAP].map_name = "ct_map";
  xh->maps[LL_DP_CT_MAP].has_pb   = 0;
  xh->maps[LL_DP_CT_MAP].max_entries = LLB_CT_MAP_ENTRIES;

  xh->maps[LL_DP_CT_STATS_MAP].map_name = "ct_stats_map";
  xh->maps[LL_DP_CT_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_CT_STATS_MAP].max_entries = LLB_CT_MAP_ENTRIES;
  xh->maps[LL_DP_CT_STATS_MAP].pbs = calloc(LLB_CT_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));
  assert(xh->maps[LL_DP_CT_STATS_MAP].pbs);

  xh->maps[LL_DP_RTV4_MAP].map_name = "rt_v4_map";
  xh->maps[LL_DP_RTV4_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV4_MAP].pb_xtid  = LL_DP_RTV4_STATS_MAP;
  xh->maps[LL_DP_RTV4_MAP].max_entries = LLB_RTV4_MAP_ENTRIES;

  xh->maps[LL_DP_RTV4_STATS_MAP].map_name = "rt_v4_stats_map";
  xh->maps[LL_DP_RTV4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV4_STATS_MAP].max_entries   = LLB_RTV4_MAP_ENTRIES;
  xh->maps[LL_DP_RTV4_STATS_MAP].pbs = calloc(LLB_RTV4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_RTV6_MAP].map_name = "rt_v6_map";
  xh->maps[LL_DP_RTV6_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV6_MAP].pb_xtid  = LL_DP_RTV6_STATS_MAP;
  xh->maps[LL_DP_RTV6_MAP].max_entries = LLB_RTV6_MAP_ENTRIES;

  xh->maps[LL_DP_RTV6_STATS_MAP].map_name = "rt_v6_stats_map";
  xh->maps[LL_DP_RTV6_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_RTV6_STATS_MAP].max_entries   = LLB_RTV6_MAP_ENTRIES;
  xh->maps[LL_DP_RTV6_STATS_MAP].pbs = calloc(LLB_RTV6_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_NH_MAP].map_name = "nh_map";
  xh->maps[LL_DP_NH_MAP].has_pb   = 0;
  xh->maps[LL_DP_NH_MAP].max_entries   = LLB_NH_MAP_ENTRIES;

  xh->maps[LL_DP_DMAC_MAP].map_name = "dmac_map";
  xh->maps[LL_DP_DMAC_MAP].has_pb   = 0;
  xh->maps[LL_DP_DMAC_MAP].max_entries   = LLB_DMAC_MAP_ENTRIES;

  xh->maps[LL_DP_TX_INTF_MAP].map_name = "tx_intf_map";
  xh->maps[LL_DP_TX_INTF_MAP].has_pb   = 0;
  xh->maps[LL_DP_TX_INTF_MAP].max_entries   = LLB_INTF_MAP_ENTRIES;

  xh->maps[LL_DP_MIRROR_MAP].map_name = "mirr_map";
  xh->maps[LL_DP_MIRROR_MAP].has_pb   = 0;
  xh->maps[LL_DP_MIRROR_MAP].max_entries  = LLB_MIRR_MAP_ENTRIES;

  xh->maps[LL_DP_TX_INTF_STATS_MAP].map_name = "tx_intf_stats_map";
  xh->maps[LL_DP_TX_INTF_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TX_INTF_STATS_MAP].max_entries = LLB_INTERFACES; 
  xh->maps[LL_DP_TX_INTF_STATS_MAP].pbs = calloc(LLB_INTERFACES, 
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_TX_BD_STATS_MAP].map_name = "tx_bd_stats_map";
  xh->maps[LL_DP_TX_BD_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_TX_BD_STATS_MAP].max_entries = LLB_INTF_MAP_ENTRIES;
  xh->maps[LL_DP_TX_BD_STATS_MAP].pbs = calloc(LLB_INTF_MAP_ENTRIES, 
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_FCV4_MAP].map_name = "fc_v4_map";
  xh->maps[LL_DP_FCV4_MAP].has_pb   = 0;
  xh->maps[LL_DP_FCV4_MAP].max_entries = LLB_FCV4_MAP_ENTRIES;

  xh->maps[LL_DP_FCV4_STATS_MAP].map_name = "fc_v4_stats_map";
  xh->maps[LL_DP_FCV4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_FCV4_STATS_MAP].max_entries = LLB_FCV4_MAP_ENTRIES;
  xh->maps[LL_DP_FCV4_STATS_MAP].pbs = calloc(LLB_FCV4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_PGM_MAP].map_name = "pgm_tbl";
  xh->maps[LL_DP_PGM_MAP].has_pb   = 0;
  xh->maps[LL_DP_PGM_MAP].max_entries = LLB_PGM_MAP_ENTRIES;

  xh->maps[LL_DP_POL_MAP].map_name = "polx_map";
  xh->maps[LL_DP_POL_MAP].has_pb   = 0;
  xh->maps[LL_DP_POL_MAP].has_pol  = 1;
  xh->maps[LL_DP_POL_MAP].max_entries = LLB_POL_MAP_ENTRIES;

  xh->maps[LL_DP_NAT_MAP].map_name = "nat_map";
  xh->maps[LL_DP_NAT_MAP].has_pb   = 1;
  xh->maps[LL_DP_NAT_MAP].pb_xtid  = LL_DP_NAT_STATS_MAP;
  xh->maps[LL_DP_NAT_MAP].max_entries = LLB_NATV4_MAP_ENTRIES;

  xh->maps[LL_DP_NAT_STATS_MAP].map_name = "nat_stats_map";
  xh->maps[LL_DP_NAT_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_NAT_STATS_MAP].max_entries = LLB_NATV4_STAT_MAP_ENTRIES;
  xh->maps[LL_DP_NAT_STATS_MAP].pbs = calloc(LLB_NATV4_STAT_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_PKT_PERF_RING].map_name = "pkt_ring";
  xh->maps[LL_DP_PKT_PERF_RING].has_pb   = 0;
  xh->maps[LL_DP_PKT_PERF_RING].max_entries = MAX_REAL_CPUS;

  xh->maps[LL_DP_SESS4_MAP].map_name = "sess_v4_map";
  xh->maps[LL_DP_SESS4_MAP].has_pb   = 1;
  xh->maps[LL_DP_SESS4_MAP].pb_xtid  = LL_DP_SESS4_STATS_MAP;
  xh->maps[LL_DP_SESS4_MAP].max_entries  = LLB_SESS_MAP_ENTRIES;

  xh->maps[LL_DP_SESS4_STATS_MAP].map_name = "sess_v4_stats_map";
  xh->maps[LL_DP_SESS4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_SESS4_STATS_MAP].max_entries = LLB_SESS_MAP_ENTRIES;
  xh->maps[LL_DP_SESS4_STATS_MAP].pbs = calloc(LLB_SESS_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_FW4_MAP].map_name = "fw_v4_map";
  xh->maps[LL_DP_FW4_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW4_MAP].pb_xtid  = LL_DP_FW_STATS_MAP;
  xh->maps[LL_DP_FW4_MAP].max_entries = LLB_FW4_MAP_ENTRIES;

  xh->maps[LL_DP_FW_STATS_MAP].map_name = "fw_stats_map";
  xh->maps[LL_DP_FW_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW_STATS_MAP].max_entries = LLB_FW4_MAP_ENTRIES + LLB_FW6_MAP_ENTRIES;
  xh->maps[LL_DP_FW_STATS_MAP].pbs = calloc(LLB_FW4_MAP_ENTRIES + LLB_FW6_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_FW6_MAP].map_name = "fw_v6_map";
  xh->maps[LL_DP_FW6_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW6_MAP].pb_xtid  = LL_DP_FW_STATS_MAP;
  xh->maps[LL_DP_FW6_MAP].max_entries = LLB_FW6_MAP_ENTRIES;

  xh->maps[LL_DP_CRC32C_MAP].map_name = "crc32c_map";
  xh->maps[LL_DP_CRC32C_MAP].has_pb   = 0;
  xh->maps[LL_DP_CRC32C_MAP].max_entries = LLB_CRC32C_ENTRIES;

  xh->maps[LL_DP_CTCTR_MAP].map_name = "ct_ctr";
  xh->maps[LL_DP_CTCTR_MAP].has_pb   = 0;
  xh->maps[LL_DP_CTCTR_MAP].max_entries = 1;

  xh->maps[LL_DP_CPU_MAP].map_name = "cpu_map";
  xh->maps[LL_DP_CPU_MAP].has_pb   = 0;
  xh->maps[LL_DP_CPU_MAP].max_entries = 128;

  xh->maps[LL_DP_LCPU_MAP].map_name = "live_cpu_map";
  xh->maps[LL_DP_LCPU_MAP].has_pb   = 0;
  xh->maps[LL_DP_LCPU_MAP].max_entries = 128;

  xh->maps[LL_DP_PPLAT_MAP].map_name = "pplat_map";
  xh->maps[LL_DP_PPLAT_MAP].has_pb   = 1;
  xh->maps[LL_DP_PPLAT_MAP].max_entries = LLB_PPLAT_MAP_ENTRIES;

  xh->maps[LL_DP_CP_PERF_RING].map_name = "cp_ring";
  xh->maps[LL_DP_CP_PERF_RING].has_pb   = 0;
  xh->maps[LL_DP_CP_PERF_RING].max_entries = MAX_REAL_CPUS;

  xh->maps[LL_DP_NAT_EP_MAP].map_name = "nat_ep_map";
  xh->maps[LL_DP_NAT_EP_MAP].has_pb   = 0;
  xh->maps[LL_DP_NAT_EP_MAP].max_entries = LLB_NAT_EP_MAP_ENTRIES;

  xh->maps[LL_DP_SOCK_RWR_MAP].map_name = "sock_rwr_map";
  xh->maps[LL_DP_SOCK_RWR_MAP].has_pb   = 0;
  xh->maps[LL_DP_SOCK_RWR_MAP].max_entries = LLB_RWR_MAP_ENTRIES;

  xh->maps[LL_DP_SOCK_PROXY_MAP].map_name = "sock_proxy_map";
  xh->maps[LL_DP_SOCK_PROXY_MAP].has_pb   = 0;
  xh->maps[LL_DP_SOCK_PROXY_MAP].max_entries = LLB_SOCK_MAP_SZ;

  strcpy(xh->psecs[0].name, LLB_SECTION_PASS);
  strcpy(xh->psecs[1].name, XDP_LL_SEC_DEFAULT);
  xh->psecs[1].setup = llb_dflt_sec_map2fd_all;

  xh->ufw4 = pdi_map_alloc("ufw4", 0, NULL, NULL);
  assert(xh->ufw4);

  xh->ufw6 = pdi_map_alloc("ufw6", 1, NULL, NULL);
  assert(xh->ufw6);

  if (xh->have_loader) {
    if (llb_loader_init(xh) != 0) {
      assert(0);
    }
  } else {
    if (!xh->have_noebpf) {
      llb_dp_maps_attach(xh);
    }
  }

  if (xh->have_mtrace) {
    if (llb_setup_kern_mon() != 0) {
      assert(0);
    }
  }

  if (xh->have_sockrwr) {
    if (llb_setup_kern_sock(xh->cgroup_dfl_path) != 0) {
      assert(0);
    }
  }

  if (xh->have_sockmap) {
    if (llb_setup_kern_sockmap(xh->cgroup_dfl_path) != 0) {
      assert(0);
    }
  }

  init_throttler(&xh->cpt, 50);

  if (proxy_main(xh->have_sockmap ? llb_sockmap_op : NULL)) {
    assert(0);
  }

  return;
}

static void
llb_clear_stats_pcpu_arr(int mfd, __u32 idx) 
{
  unsigned int nr_cpus = bpf_num_possible_cpus();
  struct dp_pb_stats values[nr_cpus];

  memset(values, 0, sizeof(values));
  if (bpf_map_update_elem(mfd, &idx, values, 0) != 0) {
    log_error("bpf_map_lookup_elem failed idx:0x%X", idx);
    return;
  }
}

static void
ll_get_stats_pcpu_arr(int mfd, __u32 idx, 
                      struct dp_pbc_stats *s,
                      dp_ts_cb_t cb)
{
  /* For percpu maps, userspace gets a value per possible CPU */
  unsigned int nr_cpus = bpf_num_possible_cpus();
  struct dp_pb_stats values[nr_cpus];
  __u64 sum_bytes = 0;
  __u64 sum_pkts = 0;
  __u64 opc = 0;
  __u64 cts;
  int i;

  if ((bpf_map_lookup_elem(mfd, &idx, values)) != 0) {
    log_error("bpf_map_lookup_elem failed idx:0x%X", idx);
    return;
  }
  
  cts = get_os_nsecs();
  opc = s->st.packets;
  if (s->lts_used == 0)
    s->lts_used = cts;

  /* Sum values from each CPU */
  for (i = 0; i < nr_cpus; i++) {
    sum_pkts  += values[i].packets;
    sum_bytes += values[i].bytes;
  }

  s->st.packets = sum_pkts;
  s->st.bytes   = sum_bytes;

  if (s->st.packets || s->st.bytes) {
#ifdef LLB_DP_STAT_DEBUG
    log_debug("IDX %d: %llu:%llu",idx,
       (unsigned long long)(s->st.packets),
       (unsigned long long)(s->st.bytes));
#endif
    if (s->st.packets > opc) {
      s->used = 1;
      s->lts_used = cts;
    } else if (cts - s->lts_used < DP_ST_LTO) {
      s->used = 1;
    }
    if (cb) {
      cb(idx, s->st.bytes, s->st.packets);
    }
  }
}

static void 
llb_fetch_map_stats_raw(int tid, dp_ts_cb_t cb, dp_tiv_cb_t vcb)
{
  int e = 0;
  llb_dp_map_t *t;

  if (tid < 0 || tid >= LL_DP_MAX_MAP) 
    return;

  t = &xh->maps[tid];

  if (t->pb_xtid) return;

  if (t->has_pb) {

    pthread_rwlock_wrlock(&t->stat_lock);
    /* FIXME : Handle non-pcpu */
    for (e = 0; e < t->max_entries; e++) {
      if (vcb && vcb(tid, e) == 0) {
        continue;
      }

      ll_get_stats_pcpu_arr(t->map_fd, e, &t->pbs[e], cb);
    }
    pthread_rwlock_unlock(&t->stat_lock);
  }
}

int
llb_fetch_map_stats_cached(int tbl, uint32_t e, int raw,
                           void *bytes, void *packets)
{
  llb_dp_map_t *t;

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) 
    return -1;

  if (tbl == LL_DP_NAT_STATS_MAP) {
    uint64_t b = 0;
    uint64_t p = 0;
    proxy_get_entry_stats((uint32_t )((e >> 4) & 0xfff), (int)(e & 0xf), &p, &b);
    *(uint64_t *)packets += p;
    *(uint64_t *)bytes += b;
  }

  if (xh->have_noebpf)
    return 0;

  t = &xh->maps[tbl];
  if (t->has_pb && t->pb_xtid > 0) { 
    if (t->pb_xtid >= LL_DP_MAX_MAP)
      return -1;
    
    t = &xh->maps[t->pb_xtid];
  }

  if (!t->has_pb) {
    return -1;
  }

  /* FIXME : Handle non-pcpu */
  pthread_rwlock_wrlock(&t->stat_lock);
  if (raw) {
    ll_get_stats_pcpu_arr(t->map_fd, e, &t->pbs[e], NULL);
  }

  if (e < t->max_entries) {
    *(uint64_t *)bytes += t->pbs[e].st.bytes;
    *(uint64_t *)packets += t->pbs[e].st.packets;
  }
  pthread_rwlock_unlock(&t->stat_lock);

  return 0;
}

static int
llb_fetch_map_stats_used(int tbl, uint32_t e, int clr, int *used)
{
  llb_dp_map_t *t;

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP)
    return -1;

  t = &xh->maps[tbl];
  if (t->has_pb && t->pb_xtid > 0) {
    if (t->pb_xtid < 0 || t->pb_xtid >= LL_DP_MAX_MAP)
      return -1;

    t = &xh->maps[t->pb_xtid];
  }

  pthread_rwlock_wrlock(&t->stat_lock);

  if (used) {
    *used = t->pbs[e].used;
  }

  if (clr) {
    t->pbs[e].used = 0;
  }
  
  pthread_rwlock_unlock(&t->stat_lock);

  return 0;
}

void 
llb_collect_map_stats(int tid)
{
  if (xh->have_noebpf) {
    return;
  }

  return llb_fetch_map_stats_raw(tid, NULL, NULL);
}

int
llb_fetch_pol_map_stats(int tid, uint32_t e, void *ppass, void *pdrop)
{
  llb_dp_map_t *t;
  struct dp_pol_tact pa;

  if (xh->have_noebpf) {
    return 0;
  }

  if (tid < 0 || tid >= LL_DP_MAX_MAP) 
    return -1;

  t = &xh->maps[tid];

  if (t->has_pol) {
    pthread_rwlock_wrlock(&t->stat_lock);

    if ((bpf_map_lookup_elem(t->map_fd, &e, &pa)) != 0) {
      log_error("bpf_map_lookup_elem failed idx:0x%X\n", e);
      pthread_rwlock_unlock(&t->stat_lock);
      return -1;
    }

    *(uint64_t *)ppass = pa.pol.ps.pass_packets;
    *(uint64_t *)pdrop = pa.pol.ps.drop_packets;

    pthread_rwlock_unlock(&t->stat_lock);

    return 0;
  }

  return -1;
}

void 
llb_map_loop_and_delete(int tid, dp_map_walker_t cb, dp_map_ita_t *it)
{
  void *pkey = NULL;
  llb_dp_map_t *t;
  uint32_t n = 0;
  int delete = 0;
  uint8_t key[1024];

  if (xh->have_noebpf) {
    return;
  }

  if (!cb) return;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return;

  memset(&key, 0, sizeof(key));
  t = &xh->maps[tid];

  while (bpf_map_get_next_key(t->map_fd, pkey, it->next_key) == 0) {
    if (n >= (t->max_entries)) break;

    if (delete) {
      llb_maptrace_uhook(tid, 0, pkey, it->key_sz, NULL, 0);
      bpf_map_delete_elem(t->map_fd, pkey);
    }

    if (bpf_map_lookup_elem(t->map_fd, it->next_key, it->val) != 0) {
      goto next;
    }

    if (it->key_sz > 0) {
      memcpy(key, it->next_key, it->key_sz);
    } else {
      memcpy(key, it->next_key, sizeof(key));
    }

    if (cb(tid, it->next_key, it)) {
      delete = 1;
    } else {
      delete = 0;
    }

next:
    pkey = key;
    n++;
  }

  if (pkey != NULL && delete) {
    llb_maptrace_uhook(tid, 0, pkey, it->key_sz, NULL, 0);
    bpf_map_delete_elem(t->map_fd, pkey);
  }

#ifdef LLB_DP_CT_DEBUG
  log_trace("TID %d entry loop count: %d", tid, n);
#endif

  return;
}

static void
llb_clear_map_stats_internal(int tid, __u32 idx, bool wipe)
{
  int e = 0;
  llb_dp_map_t *t;

  if (tid < 0 || tid >= LL_DP_MAX_MAP) 
    return;

  if (xh->have_noebpf)
    return;

  t = &xh->maps[tid];
  if (t->has_pb) {
    if (t->pb_xtid > 0) {
      if (t->pb_xtid >= LL_DP_MAX_MAP)
        return;
      t = &xh->maps[t->pb_xtid];
      if (!t->has_pb || t->pb_xtid > 0) {
        return;
      }
    }
    /* FIXME : Handle non-pcpu */
    if (!wipe) {
        llb_clear_stats_pcpu_arr(t->map_fd, idx);
    } else {
      for (e = 0; e < t->max_entries; e++) {
        llb_clear_stats_pcpu_arr(t->map_fd, e);
      }
    }
  }
}

void
llb_clear_map_stats(int tid, __u32 idx)
{
  return llb_clear_map_stats_internal(tid, idx, false);
}

int
llb_map2fd(int t)
{
  return xh->maps[t].map_fd;
}

static void ll_map_ct_rm_related(uint32_t rid, uint32_t *aids, int naid);

static int
llb_add_map_elem_nat_post_proc(void *k, void *v)
{
  struct dp_proxy_tacts *na = v;
  struct mf_xfrm_inf *ep_arm;
  uint32_t inact_aids[LLB_MAX_NXFRMS];
  int i = 0;
  int j = 0;

  memset(inact_aids, 0, sizeof(inact_aids));

  for (i = 0; i < na->nxfrm && i < LLB_MAX_NXFRMS; i++) {
    ep_arm = &na->nxfrms[i];

    if (ep_arm->inactive) {
      inact_aids[j++] = i;
    }
  }

  if (j > 0) {
    ll_map_ct_rm_related(na->ca.cidx, inact_aids, j);
  }

  return 0;

}

static int
llb_del_map_elem_nat_post_proc(void *k, void *v)
{
  struct dp_proxy_tacts *na = v;
  struct mf_xfrm_inf *ep_arm;
  uint32_t inact_aids[LLB_MAX_NXFRMS];
  int i = 0;
  int j = 0;

  memset(inact_aids, 0, sizeof(inact_aids));

  for (i = 0; i < na->nxfrm && i < LLB_MAX_NXFRMS; i++) {
    ep_arm = &na->nxfrms[i];

    if (ep_arm->inactive == 0) {
      inact_aids[j++] = i;
    }
  }

  if (j > 0) {
    ll_map_ct_rm_related(na->ca.cidx, inact_aids, j);
  }

  return 0;

}

static void
llb_nat_dec_act_sessions(uint32_t rid, uint32_t aid)
{
  llb_dp_map_t *t;
  struct dp_nat_epacts epa;

  t = &xh->maps[LL_DP_NAT_EP_MAP];

  if (t != NULL) {
    memset(&epa, 0, sizeof(epa));
    if ((bpf_map_lookup_elem_flags(t->map_fd, &rid, &epa, BPF_F_LOCK)) != 0) {
      if (epa.active_sess[aid] > 0) {
        epa.active_sess[aid]--;
        bpf_map_update_elem(t->map_fd, &rid, &epa, BPF_F_LOCK);
      }
    }
  }
}

static void
llb_nat_rst_act_sessions(uint32_t rid)
{
  llb_dp_map_t *t;
  struct dp_nat_epacts epa;
  int i;

  t = &xh->maps[LL_DP_NAT_EP_MAP];

  if (t != NULL) {
    memset(&epa, 0, sizeof(epa));
    if ((bpf_map_lookup_elem_flags(t->map_fd, &rid, &epa, BPF_F_LOCK)) != 0) {
      epa.ca.act_type = 0;
      for (i = 0; i < LLB_MAX_NXFRMS; i++) {
        epa.active_sess[i] = 0;
      }
      bpf_map_update_elem(t->map_fd, &rid, &epa, BPF_F_LOCK);
    }
  }
}

static void
llb_dp_pdik2_ufw4(struct pdi_rule *new, struct pdi_key *k) 
{
  memset(k, 0, sizeof(struct pdi_key));

  PDI_MATCH_COPY(&k->dest, &new->key.k4.dest);
  PDI_MATCH_COPY(&k->source, &new->key.k4.source);
  PDI_RMATCH_COPY(&k->sport, &new->key.k4.sport);
  PDI_RMATCH_COPY(&k->dport, &new->key.k4.dport);
  PDI_MATCH_COPY(&k->inport, &new->key.k4.inport);
  PDI_MATCH_COPY(&k->protocol, &new->key.k4.protocol);
  PDI_MATCH_COPY(&k->zone, &new->key.k4.zone);
}

static void
llb_dp_ufw42_pdik(struct pdi_rule *new, struct pdi_key *k)
{
  PDI_MATCH_COPY(&new->key.k4.dest, &k->dest);
  PDI_MATCH_COPY(&new->key.k4.source, &k->source);
  PDI_RMATCH_COPY(&new->key.k4.sport, &k->sport);
  PDI_RMATCH_COPY(&new->key.k4.dport, &k->dport);
  PDI_MATCH_COPY(&new->key.k4.inport, &k->inport);
  PDI_MATCH_COPY(&new->key.k4.protocol, &k->protocol);
  PDI_MATCH_COPY(&new->key.k4.zone, &k->zone);
}

static void
llb_dp_pdik2_ufw6(struct pdi_rule *new, struct pdi6_key *k) 
{
  memset(k, 0, sizeof(struct pdi6_key));

  PDI_MATCH6_COPY(&k->dest, &new->key.k6.dest);
  PDI_MATCH6_COPY(&k->source, &new->key.k6.source);
  PDI_RMATCH_COPY(&k->sport, &new->key.k6.sport);
  PDI_RMATCH_COPY(&k->dport, &new->key.k6.dport);
  PDI_MATCH_COPY(&k->inport, &new->key.k6.inport);
  PDI_MATCH_COPY(&k->protocol, &new->key.k6.protocol);
  PDI_MATCH_COPY(&k->zone, &new->key.k6.zone);
}

static void
llb_dp_ufw62_pdik(struct pdi_rule *new, struct pdi6_key *k)
{
  PDI_MATCH6_COPY(&new->key.k6.dest, &k->dest);
  PDI_MATCH6_COPY(&new->key.k6.source, &k->source);
  PDI_RMATCH_COPY(&new->key.k6.sport, &k->sport);
  PDI_RMATCH_COPY(&new->key.k6.dport, &k->dport);
  PDI_MATCH_COPY(&new->key.k6.inport, &k->inport);
  PDI_MATCH_COPY(&new->key.k6.protocol, &k->protocol);
  PDI_MATCH_COPY(&new->key.k6.zone, &k->zone);
}

static void
llb_dp_pdiop2_ufwa(struct pdi_rule *new, struct dp_fw_tact *fwa) 
{
  memset(fwa, 0, sizeof(*fwa));
  fwa->ca.cidx = new->data.rid;
  fwa->ca.mark = new->data.opts.mark;
  fwa->ca.record = new->data.opts.record;

  switch (new->data.op) {
  case PDI_SET_DROP:
    fwa->ca.act_type = DP_SET_DROP;
    break;
  case PDI_SET_TRAP:
    fwa->ca.act_type = DP_SET_TOCP;
    break;
  case PDI_SET_RDR:
    fwa->ca.act_type = DP_SET_RDR_PORT;
    fwa->port_act.oport = new->data.opts.port;
    break;
  case PDI_SET_FWD:
    fwa->ca.act_type = DP_SET_NOP;
    break;
  default:
    break;
  }
}

static void
llb_dp_ufw2pdiop(struct pdi_rule *new, struct dp_fw_tact *fwa)
{
  new->data.rid = fwa->ca.cidx;
  new->data.pref = fwa->ca.oaux; // Overloaded field
  new->data.opts.mark = fwa->ca.mark;
  new->data.opts.record = fwa->ca.record;

  switch (fwa->ca.act_type) {
  case DP_SET_DROP:
    new->data.op = PDI_SET_DROP;
    break;
  case DP_SET_TOCP:
    new->data.op = PDI_SET_TRAP;
    break;
  case DP_SET_RDR_PORT:
    new->data.op = PDI_SET_RDR;
    new->data.opts.port = fwa->port_act.oport;
    break;
  case DP_SET_NOP:
    new->data.op = PDI_SET_FWD;
  default:
    break; 
  }
}

static void ll_map_ct_rm_any(void);

int
llb_add_mf_map_elem__(int tbl, void *k, void *v)
{
  int ret = 0;
  int n = 0;
  int nr = 0;
  struct dp_fwv4_ent p = { 0 };
  struct dp_fwv6_ent p6 = { 0 };

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
    
    if (!new) return -1;

    llb_dp_ufw42_pdik(new, &e->k);
    llb_dp_ufw2pdiop(new, &e->fwa);

    ret = pdi_rule_insert(xh->ufw4, new, &nr);
    if (ret != 0) {
      free(new);
      if (ret == -EEXIST) {
        return 0;
      }
      return -1;
    }

    PDI_MAP_LOCK(xh->ufw4);
    FOR_EACH_PDI_ENT(xh->ufw4, new) {
      if (n == 0 || n >= nr) {
        memset(&p, 0, sizeof(p));
        llb_dp_pdik2_ufw4(new, &p.k);
        llb_dp_pdiop2_ufwa(new, &p.fwa);
        if (n == 0) {
          PDI_VAL_INIT(&p.k.nr, xh->ufw4->nr);
        }
        ret = bpf_map_update_elem(llb_map2fd(tbl), &n, &p, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }  
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw4);

  } else if (tbl == LL_DP_FW6_MAP) {
    struct dp_fwv6_ent *e6 = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));

    if (!new) return -1;

    llb_dp_ufw62_pdik(new, &e6->k);
    llb_dp_ufw2pdiop(new, &e6->fwa);

    ret = pdi_rule_insert(xh->ufw6, new, &nr);
    if (ret != 0) {
      free(new); 
      if (ret == -EEXIST) {
        return 0;
      }
      return -1;
    }

    PDI_MAP_LOCK(xh->ufw6);
    FOR_EACH_PDI_ENT(xh->ufw6, new) {
      if (n == 0 || n >= nr) {
        memset(&p6, 0, sizeof(p6));
        llb_dp_pdik2_ufw6(new, &p6.k);
        llb_dp_pdiop2_ufwa(new, &p6.fwa);
        if (n == 0) {
          PDI_VAL_INIT(&p6.k.nr, xh->ufw6->nr);
        }
        ret = bpf_map_update_elem(llb_map2fd(tbl), &n, &p6, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }  
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw6);
  }

  if (ret == 0) ll_map_ct_rm_any();
  return ret;
}

static int
llb_conv_nat2proxy(void *k, void *v, struct proxy_ent *pent, struct proxy_arg *pval)
{
  struct dp_nat_key *nat_key = k;
  struct dp_proxy_tacts *dat = v;
  int i = 0;
  int j = 0;

  pent->xip = nat_key->daddr[0];
  pent->xport = nat_key->dport;
  pent->protocol = nat_key->l4proto;

  strncpy(pval->host_url, (const char *)dat->host_url, sizeof(pval->host_url) - 1);
  pval->host_url[sizeof(pval->host_url) - 1] = '\0';

  if (!strcmp(pval->host_url, "")) {
    char ab1[INET6_ADDRSTRLEN];
    const char *host = inet_ntop(AF_INET, (struct in_addr *)&pent->xip, ab1, INET_ADDRSTRLEN);
    if (host != NULL) {
      sprintf(pval->host_url, "%s:%u", host, ntohs(pent->xport));
    }
  }

  for (i = 0; i < LLB_MAX_NXFRMS && i < MAX_PROXY_EP; i++) {
    struct mf_xfrm_inf *mf = &dat->nxfrms[i];
    struct proxy_ent *proxy_ep = &pval->eps[j];

    if (mf->inactive) continue;

    proxy_ep->xip = mf->nat_xip[0];
    proxy_ep->xport = mf->nat_xport;
    proxy_ep->protocol = nat_key->l4proto;

    j++;
  }

  if (j <= 0) {
    return -1;
  }

  if (dat->sel_type == NAT_LB_SEL_N2) {
    pval->proxy_mode = PROXY_MODE_ALL;
    pval->select =  PROXY_SEL_N2;
  }

  if (dat->sec_mode == SEC_MODE_HTTPS) {
    pval->have_ssl = 1;
  } else if (dat->sec_mode == SEC_MODE_HTTPS_E2E) {
    pval->have_ssl = 1;
    pval->have_epssl = 1;
  }

  pval->_id = dat->ca.cidx;
  pval->n_eps = j;
  return 0;
}

int
llb_add_map_elem(int tbl, void *k, void *v)
{
  int ret = -EINVAL;
  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) {
    return ret; 
  }

  XH_LOCK();

  /* Any table which has stats pb needs to get stats cleared before use */
  if (tbl == LL_DP_NAT_MAP ||
      tbl == LL_DP_TMAC_MAP ||
      tbl == LL_DP_FW4_MAP  ||
      tbl == LL_DP_FW6_MAP  ||
      tbl == LL_DP_RTV4_MAP) {
    __u32 cidx = 0;

    if (tbl == LL_DP_FW4_MAP) {
      struct dp_fwv4_ent *e = k;
      cidx = e->fwa.ca.cidx;
    } else if (tbl == LL_DP_FW6_MAP) {
      struct dp_fwv6_ent *e = k;
      cidx = e->fwa.ca.cidx;
    } else {
      struct dp_cmn_act *ca = v;
      cidx = ca->cidx;
    }

    if (tbl == LL_DP_NAT_MAP) {
      int aid = 0;
      for (aid = 0; aid < LLB_MAX_NXFRMS; aid++) {
        llb_clear_map_stats(tbl, LLB_NAT_STAT_CID(cidx, aid));
        llb_nat_rst_act_sessions(cidx);
      }
    } else {
      llb_clear_map_stats(tbl, cidx);
    }
  }

  if (tbl == LL_DP_NAT_MAP) {
    struct dp_nat_key *nk = k;
    struct dp_proxy_tacts *nv = v;
    struct proxy_ent pk = { 0 };
    struct proxy_arg pv = { 0 };

    if (nv->ca.act_type == DP_SET_FULLPROXY &&
        (nk->l4proto == IPPROTO_TCP || nk->l4proto == IPPROTO_SCTP) && nk->v6 == 0) {
      llb_conv_nat2proxy(k, v, &pk, &pv);
      // FIXME
      ret = proxy_add_entry(&pk, &pv);
      goto out;
    }
  }

  if (xh->have_noebpf) {
    ret = 0;
    goto ulock_out;
  }

  if (tbl == LL_DP_FW4_MAP || tbl == LL_DP_FW6_MAP) {
    ret = llb_add_mf_map_elem__(tbl, k, v);
  } else {
    ret = bpf_map_update_elem(llb_map2fd(tbl), k, v, 0);
  }
out:
  if (ret != 0) {
    ret = -EFAULT;
  } else {
    /* Need some post-processing for certain maps */
    if (tbl == LL_DP_NAT_MAP) {
      llb_add_map_elem_nat_post_proc(k, v);
    }
  }
ulock_out:
  XH_UNLOCK();

  return ret;
}

static int
ll_map_elem_cmp_cidx(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  uint32_t cidx;

  if (!it|| !it->uarg || !it->val) return 0;

  cidx = *(uint32_t *)it->uarg;

  if (tid == LL_DP_CT_MAP || 
      tid == LL_DP_TMAC_MAP ||
      tid == LL_DP_FCV4_MAP ||
      tid == LL_DP_RTV4_MAP) {
    struct dp_cmn_act *ca = it->val;
    if (ca->cidx == cidx) return 1;
  }

  return 0;
}

static void
llb_del_map_elem_with_cidx(int tbl, uint32_t cidx)
{
  dp_map_ita_t it;
  uint8_t skey[1024];
  uint8_t sval[1024];

  memset(&it, 0, sizeof(it));
  memset(&skey, 0, sizeof(skey));
  memset(&sval, 0, sizeof(sval));

  it.next_key = &skey;
  it.val = &sval;
  it.uarg = &cidx;

  llb_map_loop_and_delete(tbl, ll_map_elem_cmp_cidx, &it);
}

int 
llb_del_mf_map_elem__(int tbl, void *k)
{
  int ret = 0;
  int n = 0;
  int nr = 0;
  struct dp_fwv4_ent p = { 0 };
  struct dp_fwv6_ent p6 = { 0 };

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
    
    if (!new) return -1;

    llb_dp_ufw42_pdik(new, &e->k);
    llb_dp_ufw2pdiop(new, &e->fwa) ;

    ret = pdi_rule_delete(xh->ufw4, &new->key, new->data.pref, &nr);
    if (ret != 0) {
      free(new);
      return -1;
    }

    free(new);

    PDI_MAP_LOCK(xh->ufw4);
    FOR_EACH_PDI_ENT(xh->ufw4, new) {
      if (n == 0 || n >= nr) {
        memset(&p, 0, sizeof(p));
        llb_dp_pdik2_ufw4(new, &p.k);
        llb_dp_pdiop2_ufwa(new, &p.fwa);
        if (n == 0) {
          PDI_VAL_INIT(&p.k.nr, xh->ufw4->nr);
        }
        ret = bpf_map_update_elem(llb_map2fd(tbl), &n, &p, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw4);

    while (n < LLB_FW4_MAP_ENTRIES) {
      memset(&p, 0, sizeof(p));
      bpf_map_update_elem(llb_map2fd(tbl), &n, &p, 0);
      n++;
    }
  } else if (tbl == LL_DP_FW6_MAP) {
    struct dp_fwv6_ent *e6 = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
    
    if (!new) return -1;

    llb_dp_ufw62_pdik(new, &e6->k);
    llb_dp_ufw2pdiop(new, &e6->fwa) ;

    ret = pdi_rule_delete(xh->ufw6, &new->key, new->data.pref, &nr);
    if (ret != 0) {
      free(new);
      return -1;
    }

    free(new);

    PDI_MAP_LOCK(xh->ufw6);
    FOR_EACH_PDI_ENT(xh->ufw6, new) {
      if (n == 0 || n >= nr) {
        memset(&p6, 0, sizeof(p6));
        llb_dp_pdik2_ufw6(new, &p6.k);
        llb_dp_pdiop2_ufwa(new, &p6.fwa);
        if (n == 0) {
          PDI_VAL_INIT(&p6.k.nr, xh->ufw6->nr);
        }
        ret = bpf_map_update_elem(llb_map2fd(tbl), &n, &p6, 0);
        if (ret != 0) {
          ret = -EFAULT;
        }
      }
      n++;
    }
    PDI_MAP_ULOCK(xh->ufw6);

    while (n < LLB_FW6_MAP_ENTRIES) {
      memset(&p6, 0, sizeof(p6));
      bpf_map_update_elem(llb_map2fd(tbl), &n, &p6, 0);
      n++;
    }
  }

  if (ret == 0) ll_map_ct_rm_any();

  return ret;
}

int
llb_del_map_elem_wval(int tbl, void *k, void *v)
{
  int ret = -EINVAL;
  struct dp_proxy_tacts t = { 0 };

  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) {
    return ret;
  }

  XH_LOCK();

  /* Need some pre-processing for certain maps */
  if (tbl == LL_DP_NAT_MAP) {
    struct dp_nat_key *nk = k;
    struct dp_proxy_tacts *nv = v;
    struct proxy_ent pk = { 0 };
    struct proxy_arg pa = { 0 };

    assert(nv);

    if (nv->ca.act_type == DP_SET_FULLPROXY &&
        (nk->l4proto == IPPROTO_TCP || nk->l4proto == IPPROTO_SCTP) && nk->v6 == 0) {
      llb_conv_nat2proxy(nk, nv, &pk, &pa);
      proxy_delete_entry(&pk, &pa);
    }

    if (xh->have_noebpf) {
      XH_UNLOCK();
      return 0;
    }

    ret = bpf_map_lookup_elem(llb_map2fd(tbl), k, &t);
    if (ret != 0) {
      XH_UNLOCK();
      return -EINVAL;
    }
  }

  if (xh->have_noebpf) {
    XH_UNLOCK();
    return 0;
  }

  if (tbl == LL_DP_FW4_MAP || tbl == LL_DP_FW6_MAP) {
    ret = llb_del_mf_map_elem__(tbl, k);
  } else {
    ret = bpf_map_delete_elem(llb_map2fd(tbl), k);
  }
  if (ret != 0) {
    ret = -EFAULT;
  }

  /* Need some post-processing for certain maps */
  if (tbl == LL_DP_NAT_MAP) {
    llb_del_map_elem_nat_post_proc(k, &t);
  }

  XH_UNLOCK();

  return ret;
}

int
llb_del_map_elem(int tbl, void *k)
{
  return llb_del_map_elem_wval(tbl, k, NULL);
}

unsigned long long
get_os_usecs(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((unsigned long long)ts.tv_sec * 1000000UL) + ts.tv_nsec/1000;
}

unsigned long long
get_os_nsecs(void)
{
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static int
ll_fcmap_ent_has_aged(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  struct dp_fc_tacts *fc_val;
  uint64_t curr_ns;

  if (!it|| !it->uarg || !it->val) return 0;

  curr_ns = *(uint64_t *)it->uarg;
  fc_val = it->val;

  if (fc_val->its  &&
      curr_ns - fc_val->its > FC_V4_CPTO) {
    return 1;
  }

  return 0;
}

static void
ll_age_fcmap(void)
{
  dp_map_ita_t it;
  struct dp_fcv4_key next_key;
  struct dp_fc_tacts *fc_val;
  uint64_t ns = get_os_nsecs();

  if (xh->have_noebpf) {
    return;
  }

  if (ns - xh->lfcts < FC_SWEEP_PERIOD) {
    return;
  }

  xh->lfcts = ns;

  fc_val = calloc(1, sizeof(*fc_val));
  if (!fc_val) return;

  memset(&next_key, 0, sizeof(next_key));
  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = fc_val;
  it.uarg = &ns;

  XH_LOCK();
  llb_map_loop_and_delete(LL_DP_FCV4_MAP, ll_fcmap_ent_has_aged, &it);
  XH_UNLOCK();
  if (fc_val) free(fc_val);
}

typedef struct ct_arg_struct 
{
  uint64_t curr_ns;
  uint32_t rid;
  uint32_t aid[LLB_MAX_NXFRMS];
  int n_aids;
  int n_aged;
  int dir;
} ct_arg_struct_t;

static int
ctm_proto_xfk_init(struct dp_ct_key *key,
                   struct dp_ct_tact *adat,
                   struct dp_ct_key *xkey,
                   struct dp_ct_key *okey)
{
  nxfrm_inf_t *xi;

  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport;
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;
  xkey->ident = key->ident;
  xkey->type = key->type;

  xi = &adat->ctd.xi;

  if (xi->dsr || adat->ctd.pi.frag) {
    return 0;
  }

  /* Apply NAT xfrm if needed */
  if (xi->nat_flags & LLB_NAT_DST) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->saddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->daddr, xi->nat_rip);
    }
    if (key->l4proto != IPPROTO_ICMP) {
        if (xi->nat_xport)
          xkey->sport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & LLB_NAT_SRC) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->daddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->saddr, xi->nat_rip);
    }
    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & LLB_NAT_HDST) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
    }
  }
  if (xi->nat_flags & LLB_NAT_HSRC) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
    }
  }

  return 0;
}

static void
ll_send_ctep_reset(struct dp_ct_key *ep, struct dp_ct_tact *adat)
{
  struct mkr_args r;
  ct_tcp_pinf_t *ts = &adat->ctd.pi.t;

  if (ep->l4proto != IPPROTO_TCP) {
    return;
  }

  if (ts->state != CT_TCP_EST) {
    return;
  }

  memset(&r, 0, sizeof(r));

  if (ep->v6 == 0) {
    r.sip[0] = ntohl(ep->daddr[0]);
    r.dip[0] = ntohl(ep->saddr[0]);
  } else {
    memcpy(r.sip, ep->daddr, 16);
    memcpy(r.dip, ep->saddr, 16);
    r.v6 = 1;
  }
  r.sport = ntohs(ep->dport);
  r.dport = ntohs(ep->sport);
  r.protocol = ep->l4proto;
  r.t.seq = ntohl(adat->ctd.pi.t.tcp_cts[CT_DIR_IN].pack);
  r.t.rst = 1;

  create_xmit_raw_tcp(&r);
}

static void
ll_ct_get_state(struct dp_ct_key *key, struct dp_ct_tact *adat, bool *est, uint64_t *to, bool *bidir)
{
  struct dp_ct_dat *dat = &adat->ctd;

  *bidir = true;

  if (key->l4proto == IPPROTO_TCP) {
    ct_tcp_pinf_t *ts = &dat->pi.t;

    if (ts->state & CT_TCP_FIN_MASK ||
        ts->state & CT_TCP_ERR ||
        ts->state & CT_TCP_SYNC_MASK ||
        ts->state == CT_TCP_CLOSED) {
      *to = CT_TCP_FN_CPTO;
    } else if (ts->state == CT_TCP_EST ||
               ts->state == CT_TCP_PEST ) {
      *est = true;
    }
  } else if (key->l4proto == IPPROTO_UDP) {
    ct_udp_pinf_t *us = &dat->pi.u;

    *bidir = false;

    if (adat->ctd.pi.frag) {
      *to = CT_UDP_FN_CPTO;
    } else if (us->state & (CT_UDP_UEST|CT_UDP_EST)) {
      *to = CT_UDP_EST_CPTO;
      *est = true;
    } else {
      *to = CT_UDP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_ICMP ||
             key->l4proto == IPPROTO_ICMPV6) {
    ct_icmp_pinf_t *is = &dat->pi.i;
    if (is->state == CT_ICMP_REPS) {
      *est = true;
      *to = CT_ICMP_EST_CPTO;
    } else {
      *to = CT_ICMP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_SCTP) {
    ct_sctp_pinf_t *ss = &dat->pi.s;

    if (ss->state & CT_SCTP_FIN_MASK ||
        ss->state & CT_SCTP_ERR ||
        (ss->state & CT_SCTP_INIT_MASK && ss->state != CT_SCTP_EST) ||
        ss->state == CT_SCTP_CLOSED) {
      *to = CT_SCTP_FN_CPTO;
    } else if (ss->state == CT_SCTP_EST) {
      *est = true;
    }
  }
}

static void __always_inline
dp_ct_related_fc_rm(struct dp_ct_key *ctk)
{
  struct dp_fcv4_key key;

  if (ctk->v6 || ctk->ident || ctk->type) {
    return;
  }

  key.daddr      = ctk->daddr4;
  key.saddr      = ctk->saddr4;
  key.sport      = ctk->sport;
  key.dport      = ctk->dport;
  key.l4proto    = ctk->l4proto;
  key.pad        = 0;
  key.in_port    = 0;

  bpf_map_delete_elem(llb_map2fd(LL_DP_FCV4_MAP), &key);
  return;
}

static int
ll_ct_map_ent_has_aged(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  struct dp_ct_key *key = k;
  struct dp_ct_key xkey;
  struct dp_ct_key okey;
  struct dp_ct_dat *dat;
  struct dp_ct_tact *adat;
  struct dp_ct_tact axdat;
  ct_arg_struct_t *as;
  uint64_t curr_ns;
  uint64_t latest_ns;
  int used1 = 0;
  int used2 = 0;
  int any_used = 0;
  bool est = false;
  bool has_nat = false;
  bool bidir = true;
  uint64_t to = CT_V4_CPTO;
  char dstr[INET6_ADDRSTRLEN];
  char sstr[INET6_ADDRSTRLEN];
  uint64_t bytes, pkts;
  llb_dp_map_t *t;

  if (!it|| !it->uarg || !it->val) return 0;

  as = it->uarg;
  curr_ns = as->curr_ns;
  adat = it->val;
  dat = &adat->ctd;

  if (as->dir >= 0 && as->dir != adat->ctd.dir) {
    return 0;
  }

  if (key->v6 == 0) {
    inet_ntop(AF_INET, key->saddr, sstr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, key->daddr, dstr, INET_ADDRSTRLEN);
  } else {
    inet_ntop(AF_INET6, key->saddr, sstr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, key->daddr, dstr, INET6_ADDRSTRLEN);
  }

  if (adat->ctd.xi.nat_flags) {
    has_nat = true;
  }

  ctm_proto_xfk_init(key, adat, &xkey, &okey);

  t = &xh->maps[LL_DP_CT_MAP];

  if (adat->ctd.pi.frag) {
    memset(&axdat, 0, sizeof(axdat));
  } else if (bpf_map_lookup_elem(t->map_fd, &xkey, &axdat) != 0) {
    if (key->v6 == 0) {
      inet_ntop(AF_INET, xkey.saddr, sstr, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, xkey.daddr, dstr, INET_ADDRSTRLEN);
    } else {
      inet_ntop(AF_INET6, xkey.saddr, sstr, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, xkey.daddr, dstr, INET6_ADDRSTRLEN);
    }

    ll_ct_get_state(&xkey, &axdat, &est, &to, &bidir);

    if (est && curr_ns - adat->lts < CT_MISMATCH_FN_CPTO) {
      return 0;
    }

    dp_ct_related_fc_rm(key);

    log_trace("ct: rdir not found #%s:%d -> %s:%d (%d)#",
         sstr, ntohs(xkey.sport),
         dstr, ntohs(xkey.dport),
         xkey.l4proto);
    llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
    return 1;
  }

  if (adat->lts > axdat.lts) {
    latest_ns = adat->lts;
  } else {
    latest_ns = axdat.lts;
  }

  llb_fetch_map_stats_cached(LL_DP_CT_STATS_MAP, adat->ca.cidx, 1, &bytes, &pkts);
  llb_fetch_map_stats_cached(LL_DP_CT_STATS_MAP, axdat.ca.cidx, 1, &bytes, &pkts);

  ll_ct_get_state(key, adat, &est, &to, &bidir);

  if (curr_ns < latest_ns) return 0;

  if (est && adat->ito != 0) {
    to = adat->ito;
  }

  /* CT is allocated both for current and reverse direction */
  llb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, adat->ca.cidx, 1, &used1);
  llb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, axdat.ca.cidx, 1, &used2);

  if (bidir) {
    any_used = used1 && used2;
  } else {
    any_used = used1 || used2;
  }

  if (curr_ns - latest_ns > to && (!est || !any_used)) {
    log_trace("ct: #%s:%d -> %s:%d (%d)# rid:%u est:%d nat:%d (Aged:%lluns:%d:%d)",
         sstr, ntohs(key->sport),
         dstr, ntohs(key->dport),  
         key->l4proto, dat->rid,
         est, has_nat, curr_ns - latest_ns,
         used1, used2);
    ll_send_ctep_reset(key, adat);
    llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
    if (adat->ctd.xi.nat_flags) {
      llb_nat_dec_act_sessions(adat->ctd.rid, adat->ctd.aid);
    }

    if (!adat->ctd.pi.frag) {
      ll_send_ctep_reset(&xkey, &axdat);
      llb_maptrace_uhook(LL_DP_CT_MAP, 0, &xkey, sizeof(xkey), NULL, 0);
      bpf_map_delete_elem(t->map_fd, &xkey);
      dp_ct_related_fc_rm(&xkey);
      llb_clear_map_stats(LL_DP_CT_STATS_MAP, axdat.ca.cidx);
    }
    dp_ct_related_fc_rm(key);
    return 1;
  }

#ifdef LLB_DP_CT_DEBUG
  log_trace("ct f(%d) alive: #%s:%d -> %s:%d (%d)# "
         "rid:%u est:%d nat:%d (Diff:%llus:TO:%llus,%d:%d)",
         adat->ctd.pi.frag,
         sstr, ntohs(key->sport),
         dstr, ntohs(key->dport),
         key->l4proto, dat->rid,
         est, has_nat, (curr_ns - latest_ns)/1000000000,
         to/1000000000,
         used1, used2);
#endif

  return 0;
}

static void
ll_age_ctmap(void)
{
  dp_map_ita_t it;
  struct dp_ct_key next_key;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  uint64_t ns = get_os_nsecs();

  if (xh->have_noebpf) {
    return;
  }

  adat = calloc(1, sizeof(*adat));
  if (!adat) return;

  as = calloc(1, sizeof(*as));
  if (!as) {
    free(adat);
    return;
  }

  as->curr_ns = ns;
  as->dir = CT_DIR_IN;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = adat;
  it.uarg = as;

  XH_LOCK();
  if (lost > 0) {
    log_error("PerfBuf Lost count %lu", lost);
    lost = 0;
  }

  llb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_has_aged, &it);
  if (ns - xh->lctts > 120000000000) {
    as->dir = CT_DIR_OUT;
    llb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_has_aged, &it);
    xh->lctts = ns;
  }
  XH_UNLOCK();
  if (adat) free(adat);
  if (as) free(as);
}

void
llb_xh_lock(void)
{
  XH_MPLOCK();
}

void
llb_xh_unlock(void)
{
  XH_MPUNLOCK();
}

void
llb_age_map_entries(int tbl)
{
  XH_MPLOCK();
  switch (tbl) {
  case LL_DP_FCV4_MAP:
    ll_age_fcmap();
    break;
  case LL_DP_CT_MAP:
    ll_age_ctmap();
    break;
  default:
    break;
  }
  XH_MPUNLOCK();

  return;
}

void __attribute__((weak))
goProxyEntCollector(struct dp_proxy_ct_ent *e)
{
}

static void
llb_dump_proxy_entry_single(struct dp_proxy_ct_ent *e)
{
  goProxyEntCollector(e);
}

void
llb_trigger_get_proxy_entries(void)
{
  proxy_dump_entry(llb_dump_proxy_entry_single);
}

static int
ll_ct_map_ent_rm_related(int tid, void *k, void *ita)
{
  int i = 0;
  struct dp_ct_key *key = k;
  dp_map_ita_t *it = ita;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  char dstr[INET6_ADDRSTRLEN];
  char sstr[INET6_ADDRSTRLEN];

  if (!it|| !it->uarg || !it->val) return 0;

  as = it->uarg;
  adat = it->val;

  if (adat->ctd.rid != as->rid) {
    return 0;
  }

  for (i = 0; i < as->n_aids; i++) {
    if (adat->ctd.aid == as->aid[i]) {
      if (!key->v6) {
        inet_ntop(AF_INET, &key->saddr[0], sstr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key->daddr[0], dstr, INET_ADDRSTRLEN);
      } else {
        inet_ntop(AF_INET6, &key->saddr[0], sstr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &key->daddr[0], dstr, INET6_ADDRSTRLEN);
      }

      log_debug("related ct rm %s:%d -> %s:%d (%d)",
         sstr, ntohs(key->sport),
         dstr, ntohs(key->dport),
         key->l4proto);

      if (!key->v6) {
        llb_del_map_elem_with_cidx(LL_DP_FCV4_MAP, adat->ca.cidx);
      }
      llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);

      return 1;
    }
  }

  return 0;
}

static int
ll_ct_map_ent_rm_any(int tid, void *k, void *ita)
{
  struct dp_ct_key *key = k;
  dp_map_ita_t *it = ita;
  struct dp_ct_tact *adat;

  if (!it|| !it->uarg || !it->val) return 0;

  adat = it->val;

  if (!key->v6) {
    llb_del_map_elem_with_cidx(LL_DP_FCV4_MAP, adat->ca.cidx);
  }
  llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
  return 1;
}

static void
ll_map_ct_rm_related(uint32_t rid, uint32_t *aids, int naid)
{
  dp_map_ita_t it;
  int i = 0;
  struct dp_ct_key next_key;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  uint64_t ns = get_os_nsecs();

  adat = calloc(1, sizeof(*adat));
  if (!adat) return;

  as = calloc(1, sizeof(*as));
  if (!as) {
    free(adat);
    return;
  }

  as->curr_ns = ns;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = adat;
  it.uarg = as;

  as->rid = rid;
  for (i = 0; i < naid; i++) {
    as->aid[i] = aids[i];
  }
  as->n_aids = naid;

  llb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_rm_related, &it);
  if (adat) free(adat);
  if (as) free(as);
}

static void
ll_map_ct_rm_any(void)
{
  dp_map_ita_t it;
  struct dp_ct_key next_key;
  struct dp_ct_tact *adat;
  ct_arg_struct_t *as;
  uint64_t ns = get_os_nsecs();

  adat = calloc(1, sizeof(*adat));
  if (!adat) return;

  as = calloc(1, sizeof(*as));
  if (!as) {
    free(adat);
    return;
  }

  as->curr_ns = ns;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.key_sz = sizeof(next_key);
  it.val = adat;
  it.uarg = as;

  llb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_rm_any, &it);
  if (adat) free(adat);
  if (as) free(as);
}


static void
llb_set_rlims(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    log_error("Failed to increase RLIMIT_MEMLOCK limit!");
    exit(1);
  }
}

static int
llb_link_prop_add(const char *ifname,
                  void *obj,
                  int mp_type)
{
  int n = 0;
  int i = 0;
  int free = 0;
  int mfree = 0;
  llb_dp_link_t *l;
  llb_bpf_mnt_t *m;

  XH_LOCK();
  for (; n < LLB_INTERFACES; n++) {
    l = &xh->links[n];
    if (l->valid && strncmp(l->ifname, ifname, IFNAMSIZ) == 0) {
      if (l->nm > MAX_MPS) {
        XH_UNLOCK();
        return -1;
      }
      for (i = 0; i < MAX_MPS; i++) {
        m = &l->mp[i];
        if (m->mp_type == mp_type) {
          XH_UNLOCK();
          return -1;
        }
        if (m->mp_type == LL_BPF_MOUNT_NONE && !mfree)
          mfree = i + 1;
      }
     
      m = &l->mp[mfree - 1];
      m->obj = obj;
      m->mp_type = mp_type;
      l->nm++;
      
      XH_UNLOCK();
      log_debug("%s: IF-%s ref idx %d:%d type %d",
                __FUNCTION__, ifname, n, mfree - 1, mp_type);
      return 0;
    }
    if (!l->valid && !free) free = n+1;
  }

  if (free <= 0 || free >= LLB_INTERFACES) {
    XH_UNLOCK();
    return -1;
  }

  l = &xh->links[free-1]; 
  memset(l, 0, sizeof(*l));
  l->valid = 1;
  m = &l->mp[0];
  m->obj = obj;
  m->mp_type = mp_type;
  strncpy(l->ifname, ifname, IFNAMSIZ);
  l->ifname[IFNAMSIZ-1] = '\0';
  l->nm++;

  XH_UNLOCK();

  log_debug("%s: IF-%s added idx %d type %d",
            __FUNCTION__, ifname, free-1, mp_type);

  return 0;
}

static int
llb_link_prop_del(const char *ifname, int mp_type)
{
  int n = 0;
  int i = 0;
  llb_dp_link_t *l;
  llb_bpf_mnt_t *m;

  XH_LOCK();
  for (; n < LLB_INTERFACES; n++) {
    l = &xh->links[n];
    if (strncmp(l->ifname, ifname, IFNAMSIZ) == 0) {
      for (i = 0; i < MAX_MPS; i++) {
        m = &l->mp[i];
        if (m->mp_type == mp_type) {
          m->obj = NULL;
          m->mp_type = LL_BPF_MOUNT_NONE;
          l->nm--;
          break;
        }
      }
      if (l->nm == 0) {
        memset(l, 0, sizeof(*l));
      }
      XH_UNLOCK();
      return 0;
    }
  }

  XH_UNLOCK();
  return -1;
}

static int
llb_psec_add(const char *psec)
{
  int n = 0;
  int free = 0;
  int ret = -1;
  llb_dp_sect_t *s;

  XH_LOCK();
  for (; n < LLB_PSECS; n++) {
    s = &xh->psecs[n];
    if (strncmp(s->name, psec, SECNAMSIZ) == 0) {
      if (!s->valid) {
        ret = 0;
        s->valid = 1;
      } else {
        ret = 1;
      }
      s->ref++;
      XH_UNLOCK();
      return ret;
    }
    if (!s->valid && !free) free = n+1;
  }

  if (free <= 0 || free >= LLB_PSECS) {
    XH_UNLOCK();
    return -1;
  }

  s = &xh->psecs[free-1]; 
  s->valid = 1;
  s->ref = 0;
  strncpy(s->name, psec, SECNAMSIZ);
  s->name[SECNAMSIZ-1] = '\0';

  log_debug("%s: SEC-%s added idx %d", __FUNCTION__, psec, free-1);

  XH_UNLOCK();

  return 0;
}

static int
llb_psec_del(const char *psec)
{
  int n = 0;
  llb_dp_sect_t *s;

  XH_LOCK();
  for (; n < LLB_PSECS; n++) {
    s = &xh->psecs[n];
    if (strncmp(s->name, psec, SECNAMSIZ) == 0 && s->valid) {
      if (s->ref == 0)  {
        s->ref = 0;
        XH_UNLOCK();
        return 0;
      } else {
        if (s->ref > 0) {
          s->ref--;
        }
        XH_UNLOCK();
        return 0;
      }
    }
  }

  XH_UNLOCK();
  return -1;
}

static int
llb_psec_setup(const char *psec, struct bpf_object *obj)
{
  int n = 0;
  llb_dp_sect_t *s;

  XH_LOCK();
  for (; n < LLB_PSECS; n++) {
    s = &xh->psecs[n];
    if (strncmp(s->name, psec, SECNAMSIZ) == 0 && s->valid) {
      if (s->setup) {
        s->setup(obj);
        break;
      }
    } 
  }
  XH_UNLOCK();
  return 0;
}

static void * 
llb_ebpf_link_attach(struct libbpf_cfg *cfg)
{
  void *robj = NULL;

  if (cfg->tc_bpf) {
    if (!(robj = libbpf_tc_attach(cfg, 0))) {
      return NULL;
    }

    if (cfg->tc_egr_bpf) {
      struct libbpf_cfg ecfg;
      memcpy(&ecfg, cfg, sizeof(*cfg));
      ecfg.ifname = ecfg.ifname_buf;
      strcpy(ecfg.filename, LLB_FP_IMG_BPF_EGR);
      if (!(libbpf_tc_attach(&ecfg, 1))) {
        libbpf_tc_detach(cfg, 0);
        return NULL;
      }
    }

    return robj;
  } else {
    return libbpf_xdp_attach(cfg);
  }
}

static int
llb_ebpf_link_detach(struct libbpf_cfg *cfg)
{

  if (xh->have_noebpf) {
    return 0;
  }

  if (cfg->tc_bpf) {
    if (cfg->tc_egr_bpf) {
      libbpf_tc_detach(cfg, 1);
    }

    libbpf_tc_detach(cfg, 0);
    return 0;
  } else {
    return xdp_link_detach(cfg->ifindex, cfg->bpf_flags, 0);
  }
}

int
llb_dp_link_attach(const char *ifname,
                   const char *psec, 
                   int mp_type, 
                   int unload)
{
  struct bpf_object *bpf_obj;
  struct libbpf_cfg cfg;
  int nr = 0;
  int must_load = 0;

  if (xh->have_noebpf) {
    return 0;
  }

  assert(psec);
  assert(ifname);

  /* Cmdline options can change progsec */
  memset(&cfg, 0, sizeof(cfg));
  strncpy(cfg.progsec,  psec,  sizeof(cfg.progsec));

  if (mp_type == LL_BPF_MOUNT_TC) {
    strncpy(cfg.filename, xh->ll_tc_fname, sizeof(cfg.filename));
    cfg.tc_bpf = 1;
    if (xh->egr_hooks) {
      cfg.tc_egr_bpf = 1;
    }
  } else {
    strncpy(cfg.filename, xh->ll_dp_fname, sizeof(cfg.filename));
  }

  strncpy(cfg.pin_dir,  xh->ll_dp_pdir,  sizeof(cfg.pin_dir));
  if (strcmp(ifname, LLB_MGMT_CHANNEL) == 0) {
    cfg.bpf_flags |= XDP_FLAGS_SKB_MODE;
    must_load = 1;
  }

  /* Large MTU not supported until kernel 5.18 */
  cfg.bpf_flags |= XDP_FLAGS_SKB_MODE;
  cfg.bpf_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifname = (char *)&cfg.ifname_buf;
  strncpy(cfg.ifname, ifname, IF_NAMESIZE);

  cfg.ifindex = if_nametoindex(cfg.ifname);
  if (cfg.ifindex == 0 && cfg.tc_bpf == 0 && unload == 0) {
    assert(0);
  }

  if (unload) {
    llb_ebpf_link_detach(&cfg);
    llb_psec_del(psec);
    llb_link_prop_del(ifname, mp_type);
    return 0;
  }

  nr = llb_psec_add(psec);
  log_debug("%s: nr %d psection %s", cfg.filename, nr, psec);
  if (nr > 0) {
    cfg.reuse_maps = 1;
  }

  bpf_obj = llb_ebpf_link_attach(&cfg);
  if (!bpf_obj && mp_type == LL_BPF_MOUNT_XDP && must_load) {
    llb_psec_del(psec);
    return -1;
  }

  if (llb_link_prop_add(ifname, bpf_obj, mp_type) != 0) {
    xdp_link_detach(cfg.ifindex, cfg.bpf_flags, 0);
    llb_psec_del(psec);
    llb_link_prop_del(ifname, mp_type);
    return -1;
  }

  if (nr == 0 && mp_type == LL_BPF_MOUNT_XDP) {
    log_debug("setting up xdp for %s|%s", ifname, psec);
    llb_psec_setup(psec, bpf_obj);
  }

  return 0;
}

void
loxilb_set_loglevel(struct ebpfcfg *cfg)
{
  if (cfg->loglevel < 0 ||  cfg->loglevel >= LOG_FATAL) {
    cfg->loglevel = LOG_INFO;
  }

  log_set_level(cfg->loglevel);
  if (xh->logfp) {
      log_add_fp(xh->logfp, cfg->loglevel);
  }
  log_warn("ebpf: new loglevel %d", cfg->loglevel);
}

int
loxilb_main(struct ebpfcfg *cfg)
{
  FILE *fp;
  libbpf_set_print(libbpf_print_fn);

  if (!cfg->have_noebpf) {
    llb_set_rlims();
  }

  xh = calloc(1, sizeof(*xh));
  assert(xh);

  sigaction(SIGPIPE, &(struct sigaction){.sa_handler = SIG_IGN}, NULL);

  /* Save any special config parameters */
  if (cfg) {

    fp = fopen (LOXILB_DP_LOGF, "a");
    assert(fp);

    if (cfg->loglevel < 0 ||  cfg->loglevel >= LOG_FATAL) {
      cfg->loglevel = LOG_INFO;
    }
    log_set_level(cfg->loglevel);
    log_add_fp(fp, cfg->loglevel);

    xh->have_loader = !cfg->no_loader;
    xh->have_mtrace = cfg->have_mtrace;
    xh->have_ptrace = cfg->have_ptrace;
    xh->nodenum = cfg->nodenum;
    xh->logfp = fp;
    xh->have_noebpf = cfg->have_noebpf;

    // FIXME - Experimental
    xh->have_sockrwr = cfg->have_sockrwr;
    xh->have_sockmap = cfg->have_sockmap;

    xh->egr_hooks = cfg->egr_hooks;
    if (xh->have_sockrwr != 0) {
      xh->cgroup_dfl_path = CGROUP_PATH;
    }

    xh->lctts = get_os_nsecs();
    xh->lfcts = get_os_nsecs();

    if (xh->have_noebpf) {
      xh->have_loader = 0;
      xh->have_mtrace = 0;
      xh->have_ptrace = 0;
      xh->have_sockrwr = 0;
      xh->have_sockmap = 0;
      xh->egr_hooks = 0;
    }
  }

  llb_xh_init(xh);

  return 0;
}

void
llb_unload_kern_all(void)
{
  llb_unload_kern_mon();
  llb_unload_kern_sock();
  llb_unload_kern_sockmap();
  if (xh->cgfd > 0) {
    close(xh->cgfd);
    xh->cgfd = -1;
  }
}
