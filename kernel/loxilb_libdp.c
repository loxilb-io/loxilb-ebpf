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
#include <pthread.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "bpf.h"
#include "libbpf.h"

#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

#include "loxilb_libdp.h"
#include "llb_kern_mon.h"
#include "loxilb_libdp.skel.h"
#include "../common/pdi.h"
#include "../common/common_frame.h"

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
  const char *ll_dp_fname;
  const char *ll_tc_fname;
  const char *ll_dp_dfl_sec;
  const char *ll_dp_pdir;
  pthread_t pkt_thr;
  pthread_t mon_thr;
  int mgmt_ch_fd;
  int have_mtrace;
  int nodenum;
  llb_dp_map_t maps[LL_DP_MAX_MAP];
  llb_dp_link_t links[LLB_INTERFACES];
  llb_dp_sect_t psecs[LLB_PSECS];
  struct pdi_map *ufw4;
  struct pdi_map *ufw6;
} llb_dp_struct_t;

#define XH_LOCK()    pthread_rwlock_wrlock(&xh->lock)
#define XH_RD_LOCK() pthread_rwlock_rdlock(&xh->lock)
#define XH_UNLOCK()  pthread_rwlock_unlock(&xh->lock)
#define XH_BPF_OBJ() xh->links[0].obj

llb_dp_struct_t *xh;

static inline unsigned int
bpf_num_possible_cpus(void)
{
	int possible_cpus = libbpf_num_possible_cpus();
	if (possible_cpus < 0) {
		return 0;
	}
	return possible_cpus;
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
  if (level > LIBBPF_INFO)
    return 0;
  return vfprintf(stderr, format, args);
}

static void
llb_handle_pkt_event(void *ctx,
                    int cpu,
                    void *data,
                    unsigned int data_sz)
{
  struct ll_dp_pmdi *pmd = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  printf("%-8s %-5s %-7d %-16d %-3d %-16d %-8d\n", ts, "PKT", 
         pmd->ifindex, pmd->xdp_inport, pmd->table_id,
         pmd->rcode, pmd->pkt_len);

  ll_pretty_hex(pmd->data, pmd->pkt_len);
}

static void *
llb_pkt_proc_main(void *arg)
{
  struct perf_buffer *pb = arg;

  while (1) {
    perf_buffer__poll(pb, 100 /* timeout, ms */);
  } 

  /* NOT REACHED */
  return NULL;
}

static int
llb_setup_pkt_ring(struct bpf_object *bpf_obj __attribute__((unused)))
{
  struct perf_buffer *pb = NULL;
  struct perf_buffer_opts pb_opts = { 0 };
  int pkt_fd = xh->maps[LL_DP_PKT_PERF_RING].map_fd;

  if (pkt_fd < 0) return -1;

  /* Set up ring buffer polling */
  pb_opts.sample_cb = llb_handle_pkt_event;

  pb = perf_buffer__new(pkt_fd, 8 /* 32KB per CPU */, &pb_opts);
  if (libbpf_get_error(pb)) {
    fprintf(stderr, "Failed to create perf buffer\n");
    goto cleanup;
  }

  pthread_create(&xh->pkt_thr, NULL, llb_pkt_proc_main, pb);

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
llb_maptrace_output(void *ctx, int cpu, void *data, __u32 size)
{
  struct map_update_data *map_data = (struct map_update_data*)data;
  struct ll_dp_map_notif noti;

#if 0
  char out_val;
  if (map_data->updater == UPDATER_KERNEL) {
    printf("Map Updated From Kernel:\n");
  } else if (map_data->updater == UPDATER_USERMODE) {
    printf("Map Updated From User:\n");
  } else if (map_data->updater == UPDATER_SYSCALL_GET) {
    printf("Syscall used to get a map handle:\n");
  } else if (map_data->updater == UPDATER_SYSCALL_UPDATE) {
    printf("Syscall used to get a update map using handle:\n");
  } else if (map_data->updater == DELETE_KERNEL) {
    printf("Map Deleted From Kernel:\n");
  }
  printf("  PID:   %d\n",  map_data->pid);
  if (map_data->updater == UPDATER_SYSCALL_UPDATE) {
    printf("  FD:    %d\n",  map_data->map_id);
  } else {
    printf("  ID:    %d\n",  map_data->map_id);
  }
  if (map_data->name[0] != '\x00')
    printf("  Name:  %s\n",  map_data->name);
  if (map_data->key_size > 0) {
    printf("  Key:   ");
    for (int i = 0; i < map_data->key_size; i++) {
      out_val = map_data->key[i];
      printf("%02x ", out_val);
    }
    printf("\n");
  }
  if (map_data->value_size > 0 && map_data->updater != DELETE_KERNEL) {
    printf("  Value: ");
    for (int i = 0; i < map_data->value_size; i++) {
      out_val = map_data->value[i];
      printf("%02x ", out_val);
    }
    printf("\n");
  }
#endif

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
llb_setup_kern_mon(void)
{
  struct llb_kern_mon *prog;
  int err;

  // Open and load eBPF Program
  prog = llb_kern_mon__open();
  if (!prog) {
      printf("Failed to open and load BPF skeleton\n");
      return 1;
  }
  err = llb_kern_mon__load(prog);
  if (err) {
      printf("Failed to load and verify BPF skeleton\n");
      goto cleanup;
  }

  // Attach the various kProbes
  err = llb_kern_mon__attach(prog);
  if (err) {
      printf("Failed to attach BPF skeleton\n");
      goto cleanup;
  }

  // Setup Pef buffer to process events from kernel
  struct perf_buffer_opts pb_opts = { 0 } ;
  struct perf_buffer *pb;
  pb_opts.sample_cb = llb_maptrace_output;
  pb = perf_buffer__new(bpf_map__fd(prog->maps.map_events), 8, &pb_opts);
  err = libbpf_get_error(pb);
  if (err) {
    printf("failed to setup perf_buffer: %d\n", err);
    goto cleanup;
  }

  pthread_create(&xh->mon_thr, NULL, llb_maptrace_main, pb);

  return 0;

cleanup:
  llb_kern_mon__destroy(prog);
  return err < 0 ? -err : 0;

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
#endif

static int 
llb_objmap2fd(struct bpf_object *bpf_obj,
              const char *mapname)
{
  struct bpf_map *map;
  int map_fd = -1;

  map = bpf_object__find_map_by_name(bpf_obj, mapname);
  if (!map) {
    goto out;
  }

  map_fd = bpf_map__fd(map);
  printf("%s: %d\n", mapname, map_fd);
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
    fd = llb_objmap2fd(bpf_obj, xh->maps[i].map_name);  
    if (fd < 0) {
      printf("BPF: map2fd failed %s\n", xh->maps[i].map_name);
      continue;
    }
    xh->maps[i].map_fd = fd;
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
    }
  }

  /* Clean previous pins */
  if (bpf_object__unpin_maps(bpf_obj, xh->ll_dp_pdir) != 0) {
    printf("%s: Unpin maps failed\n", xh->ll_dp_pdir);
  }

  /* This will pin all maps in our bpf_object */
  err = bpf_object__pin_maps(bpf_obj, xh->ll_dp_pdir);
  if (err) {
    printf("BPF: Object pin failed\n");
    //assert(0);
  }

  llb_setup_pkt_ring(bpf_obj);

  return 0;
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
llb_mgmt_ch_init(llb_dp_struct_t *xh)
{
  int fd;
  int ret;
  struct ifreq ifr;
  char *dev = "/dev/net/tun";
  
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

  xh->maps[LL_DP_FCV4_MAP].map_name = "fc_v4_map";
  xh->maps[LL_DP_FCV4_MAP].has_pb   = 0;
  xh->maps[LL_DP_FCV4_MAP].max_entries = LLB_FCV4_MAP_ENTRIES;

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
  xh->maps[LL_DP_PKT_PERF_RING].max_entries = 128;  /* MAX_CPUS */

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
  xh->maps[LL_DP_FW4_MAP].pb_xtid  = LL_DP_FW4_STATS_MAP;
  xh->maps[LL_DP_FW4_MAP].max_entries = LLB_FW4_MAP_ENTRIES;

  xh->maps[LL_DP_FW4_STATS_MAP].map_name = "fw_v4_stats_map";
  xh->maps[LL_DP_FW4_STATS_MAP].has_pb   = 1;
  xh->maps[LL_DP_FW4_STATS_MAP].max_entries = LLB_FW4_MAP_ENTRIES;
  xh->maps[LL_DP_FW4_STATS_MAP].pbs = calloc(LLB_FW4_MAP_ENTRIES,
                                            sizeof(struct dp_pbc_stats));

  xh->maps[LL_DP_CRC32C_MAP].map_name = "crc32c_map";
  xh->maps[LL_DP_CRC32C_MAP].has_pb   = 0;
  xh->maps[LL_DP_CRC32C_MAP].max_entries = LLB_CRC32C_ENTRIES;

  xh->maps[LL_DP_CTCTR_MAP].map_name = "ct_ctr";
  xh->maps[LL_DP_CTCTR_MAP].has_pb   = 0;
  xh->maps[LL_DP_CTCTR_MAP].max_entries = 1;

  strcpy(xh->psecs[0].name, LLB_SECTION_PASS);
  strcpy(xh->psecs[1].name, XDP_LL_SEC_DEFAULT);
  xh->psecs[1].setup = llb_dflt_sec_map2fd_all;

  xh->ufw4 = pdi_map_alloc("ufw4", NULL, NULL);
  assert(xh->ufw4);

  xh->ufw6 = pdi_map_alloc("ufw6", NULL, NULL);
  assert(xh->ufw6);

  if (llb_mgmt_ch_init(xh) != 0) {
    assert(0);
  }

  if (xh->have_mtrace) {
    if (llb_setup_kern_mon() != 0) {
      assert(0);
    }
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
    fprintf(stderr,
      "ERR: bpf_map_lookup_elem failed idx:0x%X\n", idx);
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
  int i;

  if ((bpf_map_lookup_elem(mfd, &idx, values)) != 0) {
    fprintf(stderr,
      "ERR: bpf_map_lookup_elem failed idx:0x%X\n", idx);
    return;
  }
  
  opc = s->st.packets;

  /* Sum values from each CPU */
  for (i = 0; i < nr_cpus; i++) {
    sum_pkts  += values[i].packets;
    sum_bytes += values[i].bytes;
  }

  s->st.packets = sum_pkts;
  s->st.bytes   = sum_bytes;

  if (s->st.packets || s->st.bytes) {
#ifdef LLB_DP_STAT_DEBUG
    printf("IDX %d: %llu:%llu\n",idx, 
       (unsigned long long)(s->st.packets),
       (unsigned long long)(s->st.bytes));
#endif
    if (s->st.packets > opc) {
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

  t = &xh->maps[tbl];
  if (t->has_pb && t->pb_xtid > 0) { 
    if (t->pb_xtid < 0 || t->pb_xtid >= LL_DP_MAX_MAP)
      return -1;
    
    t = &xh->maps[t->pb_xtid];
  }

  /* FIXME : Handle non-pcpu */

  pthread_rwlock_wrlock(&t->stat_lock);
  if (raw) {
    ll_get_stats_pcpu_arr(t->map_fd, e, &t->pbs[e], NULL);
  }
  if (e < t->max_entries) {
    *(uint64_t *)bytes = t->pbs[e].st.bytes;
    *(uint64_t *)packets = t->pbs[e].st.packets;
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
  return llb_fetch_map_stats_raw(tid, NULL, NULL);
}

int
llb_fetch_pol_map_stats(int tid, uint32_t e, void *ppass, void *pdrop)
{
  llb_dp_map_t *t;
  struct dp_pol_tact pa;

  if (tid < 0 || tid >= LL_DP_MAX_MAP) 
    return -1;

  t = &xh->maps[tid];

  if (t->has_pol) {
    pthread_rwlock_wrlock(&t->stat_lock);

    if ((bpf_map_lookup_elem(t->map_fd, &e, &pa)) != 0) {
      fprintf(stderr,
        "ERR: bpf_map_lookup_elem failed idx:0x%X\n", e);
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
  void *key = NULL;
  llb_dp_map_t *t;
  int n = 0;

  if (!cb) return;

  if (tid < 0 || tid >= LL_DP_MAX_MAP)
    return;


  t = &xh->maps[tid];

  while (bpf_map_get_next_key(t->map_fd, key, it->next_key) == 0) {
    if (n >= t->max_entries) break;

    if (bpf_map_lookup_elem(t->map_fd, it->next_key, it->val) != 0) {
      goto next;
    }

    if (cb(tid, it->next_key, it)) {
      llb_maptrace_uhook(tid, 0, it->next_key, it->key_sz, NULL, 0);
      bpf_map_delete_elem(t->map_fd, it->next_key);
    }

next:
    key = it->next_key;
    n++;
  }

  return;
}

void 
llb_clear_map_stats(int tid, __u32 idx)
{
  int e = 0;
  llb_dp_map_t *t;

  if (tid < 0 || tid >= LL_DP_MAX_MAP) 
    return;

  t = &xh->maps[tid];
  if (t->has_pb && t->pb_xtid <= 0) {
    /* FIXME : Handle non-pcpu */
    if (idx >= 0) {
        llb_clear_stats_pcpu_arr(t->map_fd, idx);
    } else {
      for (e = 0; e < t->max_entries; e++) {
        llb_clear_stats_pcpu_arr(t->map_fd, e);
      }
    }
  } else if (t->has_pb && t->pb_xtid > 0) {
    if (t->pb_xtid < 0 || t->pb_xtid >= LL_DP_MAX_MAP)
      return;

    t = &xh->maps[t->pb_xtid];
    if (!t->has_pb || t->pb_xtid > 0) {
      return;
    }

    if (idx >= 0) {
        llb_clear_stats_pcpu_arr(t->map_fd, idx);
    }
  }
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
  struct dp_nat_tacts *na = v;
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

static void
llb_dp_pdik2_ufw4(struct pdi_rule *new, struct pdi_key *k) 
{
  memset(k, 0, sizeof(struct pdi_key));

  PDI_MATCH_COPY(&k->dest, &new->key.dest);
  PDI_MATCH_COPY(&k->source, &new->key.source);
  PDI_RMATCH_COPY(&k->sport, &new->key.sport);
  PDI_RMATCH_COPY(&k->dport, &new->key.dport);
  PDI_MATCH_COPY(&k->inport, &new->key.inport);
  PDI_MATCH_COPY(&k->protocol, &new->key.protocol);
  PDI_MATCH_COPY(&k->zone, &new->key.zone);
}

static void
llb_dp_ufw42_pdik(struct pdi_rule *new, struct pdi_key *k)
{
  PDI_MATCH_COPY(&new->key.dest, &k->dest);
  PDI_MATCH_COPY(&new->key.source, &k->source);
  PDI_RMATCH_COPY(&new->key.sport, &k->sport);
  PDI_RMATCH_COPY(&new->key.dport, &k->dport);
  PDI_MATCH_COPY(&new->key.inport, &k->inport);
  PDI_MATCH_COPY(&new->key.protocol, &k->protocol);
  PDI_MATCH_COPY(&new->key.zone, &k->zone);
}

static void
llb_dp_pdiop2_ufw4(struct pdi_rule *new, struct dp_fwv4_ent *e) 
{
  memset(&e->fwa, 0, sizeof(e->fwa));
  e->fwa.ca.cidx = new->data.rid;
  e->fwa.ca.mark = new->data.opts.mark;
  e->fwa.ca.record = new->data.opts.record;

  switch (new->data.op) {
  case PDI_SET_DROP:
    e->fwa.ca.act_type = DP_SET_DROP;
    break;
  case PDI_SET_TRAP:
    e->fwa.ca.act_type = DP_SET_TOCP;
    break;
  case PDI_SET_RDR:
    e->fwa.ca.act_type = DP_SET_RDR_PORT;
    e->fwa.port_act.oport = new->data.opts.port;
    break;
  case PDI_SET_FWD:
    e->fwa.ca.act_type = DP_SET_NOP;
    break;
  default:
    break;
  }
}

static void
llb_dp_ufw42_pdiop(struct pdi_rule *new, struct dp_fwv4_ent *e) 
{
  new->data.rid = e->fwa.ca.cidx;
  new->data.pref = e->fwa.ca.oaux; // Overloaded field
  new->data.opts.mark = e->fwa.ca.mark;
  new->data.opts.record = e->fwa.ca.record;

  switch (e->fwa.ca.act_type) {
  case DP_SET_DROP:
    new->data.op = PDI_SET_DROP;
    break;
  case DP_SET_TOCP:
    new->data.op = PDI_SET_TRAP;
    break;
  case DP_SET_RDR_PORT:
    new->data.op = PDI_SET_RDR;
    new->data.opts.port = e->fwa.port_act.oport;
    break;
  case DP_SET_NOP:
    new->data.op = PDI_SET_FWD;
  default:
    break; 
  }
}

int
llb_add_mf_map_elem__(int tbl, void *k, void *v)
{
  int ret = 0;
  int n = 0;
  int nr = 0;
  struct dp_fwv4_ent p = { 0 };

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
    
    if (!new) return -1;

    llb_dp_ufw42_pdik(new, &e->k);
    llb_dp_ufw42_pdiop(new, e) ;

    ret = pdi_rule_insert(xh->ufw4, new, &nr);
    if (ret != 0) {
      free(new);
      return -1;
    }

    PDI_MAP_LOCK(xh->ufw4);
    FOR_EACH_PDI_ENT(xh->ufw4, new) {
      if (n == 0 || n >= nr) {
        memset(&p, 0, sizeof(p));
        llb_dp_pdik2_ufw4(new, &p.k);
        llb_dp_pdiop2_ufw4(new, &p);
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
  }
  return ret;
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
      tbl == LL_DP_TMAC_MAP ||
      tbl == LL_DP_FW4_MAP  ||
      tbl == LL_DP_RTV4_MAP) {
    __u32 cidx = 0;

    if (tbl == LL_DP_FW4_MAP) {
      struct dp_fwv4_ent *e = k;
      cidx = e->fwa.ca.cidx;
    } else {
      struct dp_cmn_act *ca = v;
      cidx = ca->cidx;
    }

    llb_clear_map_stats(tbl, cidx);
  }

  if (tbl == LL_DP_FW4_MAP) {
    ret = llb_add_mf_map_elem__(tbl, k, v);
  } else {
    ret = bpf_map_update_elem(llb_map2fd(tbl), k, v, 0);
  }
  if (ret != 0) {
    ret = -EFAULT;
  } else {
    /* Need some post-processing for certain maps */
    if (tbl == LL_DP_NAT_MAP) {
      llb_add_map_elem_nat_post_proc(k, v);
    }
  }
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

  if (tbl == LL_DP_FW4_MAP) {
    struct dp_fwv4_ent *e = k;
    struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
    
    if (!new) return -1;

    llb_dp_ufw42_pdik(new, &e->k);
    llb_dp_ufw42_pdiop(new, e) ;

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
        llb_dp_pdiop2_ufw4(new, &p);
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
  }
  return ret;
}

int
llb_del_map_elem(int tbl, void *k)
{
  int ret = -EINVAL;
  uint32_t cidx = 0;
  if (tbl < 0 || tbl >= LL_DP_MAX_MAP) {
    return ret;
  }

  XH_LOCK();

  /* Need some pre-processing for certain maps */
  if (tbl == LL_DP_NAT_MAP) {
    struct dp_nat_tacts t = { 0 };
    ret = bpf_map_lookup_elem(llb_map2fd(tbl), k, &t);
    if (ret != 0) {
      XH_UNLOCK();
      return -EINVAL;
    }
    cidx = t.ca.cidx;
  }
  
  if (tbl == LL_DP_FW4_MAP) {
    ret = llb_del_mf_map_elem__(tbl, k);
  } else {
    ret = bpf_map_delete_elem(llb_map2fd(tbl), k);
  }
  if (ret != 0) {
    ret = -EFAULT;
  }

  /* Need some post-processing for certain maps */
  if (tbl == LL_DP_NAT_MAP) {
    if (cidx > 0) {
      llb_del_map_elem_with_cidx(LL_DP_CT_MAP, cidx);
      llb_clear_map_stats(LL_DP_CT_STATS_MAP, cidx);
    }
  }

  XH_UNLOCK();

  return ret;
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

  fc_val = calloc(1, sizeof(*fc_val));
  if (!fc_val) return;

  memset(&it, 0, sizeof(it));
  it.next_key = &next_key;
  it.val = fc_val;
  it.uarg = &ns;

  llb_map_loop_and_delete(LL_DP_FCV4_MAP, ll_fcmap_ent_has_aged, &it);
  if (fc_val) free(fc_val);
}

typedef struct ct_arg_struct 
{
  uint64_t curr_ns;
  uint32_t rid;
  uint32_t aid[32];
  int n_aids;
  int n_aged;
} ct_arg_struct_t;

static int
ctm_proto_xfk_init(struct dp_ct_key *key,
                   nxfrm_inf_t *xi,
                   struct dp_ct_key *xkey)
{
  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport;
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;

  if (xi->dsr) {
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

static int
ll_ct_map_ent_has_aged(int tid, void *k, void *ita)
{
  dp_map_ita_t *it = ita;
  struct dp_ct_key *key = k;
  struct dp_ct_key xkey;
  struct dp_ct_dat *dat;
  struct dp_ct_tact *adat;
  struct dp_ct_tact axdat;
  ct_arg_struct_t *as;
  uint64_t curr_ns;
  uint64_t latest_ns;
  int used1 = 0;
  int used2 = 0;
  bool est = false;
  bool has_nat = false;
  uint64_t to = CT_V4_CPTO;
  char dstr[INET6_ADDRSTRLEN];
  char sstr[INET6_ADDRSTRLEN];
  llb_dp_map_t *t;

  if (!it|| !it->uarg || !it->val) return 0;

  as = it->uarg;
  curr_ns = as->curr_ns;
  adat = it->val;
  dat = &adat->ctd;

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

  ctm_proto_xfk_init(key, &adat->ctd.xi, &xkey);

  t = &xh->maps[LL_DP_CT_MAP];
  if (bpf_map_lookup_elem(t->map_fd, &xkey, &axdat) != 0) {
    printf("rdir ct4 not found %s:%d -> %s:%d (%d)\n",
         dstr, ntohs(xkey.sport),
         sstr, ntohs(xkey.dport),  
         xkey.l4proto); 
    llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
    return 1;
  }

  if (adat->lts > axdat.lts) {
    latest_ns = adat->lts;
  } else {
    latest_ns = axdat.lts;
  }

  if (dat->dir == CT_DIR_OUT) {
    return 0;
  } 

  if (key->l4proto == IPPROTO_TCP) {
    ct_tcp_pinf_t *ts = &dat->pi.t;

    if (ts->state & CT_TCP_FIN_MASK ||
        ts->state & CT_TCP_ERR ||
        ts->state & CT_TCP_SYNC_MASK ||
        ts->state == CT_TCP_CLOSED) {
      to = CT_TCP_FN_CPTO;
    } else if (ts->state == CT_TCP_EST) {
      est = true;
    }
  } else if (key->l4proto == IPPROTO_UDP) {
    ct_udp_pinf_t *us = &dat->pi.u;
 
    if (us->state & (CT_UDP_UEST|CT_UDP_EST)) {
      to = CT_UDP_EST_CPTO;
      est = true;
    } else {
      to = CT_UDP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_ICMP ||
             key->l4proto == IPPROTO_ICMPV6) {
    ct_icmp_pinf_t *is = &dat->pi.i;
    if (is->state == CT_ICMP_REPS) {
      est = true;
      to = CT_ICMP_EST_CPTO;
    } else {
      to = CT_ICMP_FN_CPTO;
    }
  } else if (key->l4proto == IPPROTO_SCTP) {
    ct_sctp_pinf_t *ss = &dat->pi.s;

    if (ss->state & CT_SCTP_FIN_MASK ||
        ss->state & CT_SCTP_ERR ||
        (ss->state & CT_SCTP_INIT_MASK && ss->state != CT_SCTP_EST) ||
        ss->state == CT_SCTP_CLOSED) {
      to = CT_SCTP_FN_CPTO;
    } else if (ss->state == CT_SCTP_EST) {
      est = true;
    }
  }

  if (curr_ns < latest_ns) return 0;

  if (est && adat->ito != 0) {
    to = adat->ito;
  }

  /* CT is allocated both for current and reverse direction */
  llb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, adat->ca.cidx, 1, &used1);
  llb_fetch_map_stats_used(LL_DP_CT_STATS_MAP, adat->ca.cidx+1, 1, &used2);

  if (curr_ns - latest_ns > to && !used1 && !used2) {
    printf("##%s:%d -> %s:%d (%d):%u (Aged:%d:%d:%d)\n",
         sstr, ntohs(key->sport),
         dstr, ntohs(key->dport),  
         key->l4proto, dat->rid, est, has_nat, used1 || used2);
    ll_send_ctep_reset(key, adat);
    ll_send_ctep_reset(&xkey, &axdat);
    llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);
    return 1;
  }

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

  llb_map_loop_and_delete(LL_DP_CT_MAP, ll_ct_map_ent_has_aged, &it);
  if (adat) free(adat);
  if (as) free(as);
}

void
llb_age_map_entries(int tbl)
{
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

  return;
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
      printf("related ct rm %s:%d -> %s:%d (%d)\n",
         sstr, ntohs(key->sport),
         dstr, ntohs(key->dport),
         key->l4proto);

      llb_clear_map_stats(LL_DP_CT_STATS_MAP, adat->ca.cidx);

      return 1;
    }
  }

  return 0;
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
llb_set_rlims(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
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
      printf("%s: IF-%s ref idx %d:%d type %d\n", 
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

  printf("%s: IF-%s added idx %d type %d\n", 
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
      if (s->valid) {
        s->ref++;
        ret = s->ref;
        XH_UNLOCK();
        return ret;
      } else {
        s->valid = 1;
        s->ref = 0;
        XH_UNLOCK();
        return 0;
      }
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

  printf("%s: SEC-%s added idx %d\n", __FUNCTION__, psec, free-1);

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
        s->valid = 0;
        s->ref = 0;
        XH_UNLOCK();
        return 0;
      } else {
        s->ref--;
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

static void
llb_sys_exec(char *str)
{
  (void)(system(str)+1);
}

static void * 
llb_ebpf_link_attach(struct config *cfg)
{
  char cmd[PATH_MAX];
  if (cfg->tc_bpf) {
    /* ntc is netlox's modified tc tool */
    sprintf(cmd, "ntc qdisc add dev %s clsact 2>&1 >/dev/null", cfg->ifname);
    llb_sys_exec(cmd);
    printf("%s\n", cmd);    

    sprintf(cmd, "ntc filter add dev %s ingress bpf da obj %s sec %s 2>&1",
            cfg->ifname, cfg->filename, cfg->progsec);
    llb_sys_exec(cmd);
    printf("%s\n", cmd);

#ifdef HAVE_DP_EGR_HOOK
    sprintf(cmd, "ntc filter add dev %s egress bpf da obj %s sec %s 2>&1",
            cfg->ifname, cfg->filename, cfg->progsec);
    llb_sys_exec(cmd);
    printf("%s\n", cmd);
#endif

    return 0;
  } else {
    return load_bpf_and_xdp_attach(cfg);
  }
}

static int
llb_ebpf_link_detach(struct config *cfg)
{
  char cmd[PATH_MAX];

  if (cfg->tc_bpf) {
    /* ntc is netlox's modified tc tool */
#ifdef HAVE_DP_EGR_HOOK
    sprintf(cmd, "ntc filter del dev %s egress 2>&1", cfg->ifname);
    printf("%s\n", cmd);
    llb_sys_exec(cmd);
#endif

    sprintf(cmd, "ntc filter del dev %s ingress 2>&1", cfg->ifname);
    printf("%s\n", cmd);    
    llb_sys_exec(cmd);
    return 0;
  } else {
    return xdp_link_detach(cfg->ifindex, cfg->xdp_flags, 0);
  }
}

int
llb_dp_link_attach(const char *ifname,
                   const char *psec, 
                   int mp_type, 
                   int unload)
{
  struct bpf_object *bpf_obj;
	struct config cfg;
  int nr = 0;

  assert(psec);
  assert(ifname);

	/* Cmdline options can change progsec */
  memset(&cfg, 0, sizeof(cfg));
  strncpy(cfg.progsec,  psec,  sizeof(cfg.progsec));

  if (mp_type == LL_BPF_MOUNT_TC) {
    strncpy(cfg.filename, xh->ll_tc_fname, sizeof(cfg.filename));
    cfg.tc_bpf = 1;
  } else {
    strncpy(cfg.filename, xh->ll_dp_fname, sizeof(cfg.filename));
  }

  strncpy(cfg.pin_dir,  xh->ll_dp_pdir,  sizeof(cfg.pin_dir));
  if (strcmp(ifname, LLB_MGMT_CHANNEL) == 0)
    cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;
  cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
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
  printf("NR %d PSEC %s %s\n", nr, psec, cfg.filename);
  if (nr > 0) {
    cfg.reuse_maps = 1;
  }

  bpf_obj = llb_ebpf_link_attach(&cfg);
  if (!bpf_obj && mp_type == LL_BPF_MOUNT_XDP) {
    llb_psec_del(psec);
    return -1;
  }

  if (llb_link_prop_add(ifname, bpf_obj, mp_type) != 0) {
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    llb_psec_del(psec);
    llb_link_prop_del(ifname, mp_type);
    return -1;
  }

  if (nr == 0 && mp_type == LL_BPF_MOUNT_XDP) {
    printf("Setting up for %s|%s\n", ifname, psec);
    llb_psec_setup(psec, bpf_obj);
  }

  return 0;
}

int
loxilb_main(struct ebpfcfg *cfg)
{
  libbpf_set_print(libbpf_print_fn);
  llb_set_rlims();

  xh = calloc(1, sizeof(*xh));
  assert(xh);

  /* Save any special config parameters */
  if (cfg) {
    xh->have_mtrace = cfg->have_mtrace;
    xh->nodenum = cfg->nodenum;
  }

  llb_xh_init(xh);
  return 0;
}
