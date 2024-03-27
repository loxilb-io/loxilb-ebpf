/* 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <stdint.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/common_pdi.h"
#include "../common/llb_dpapi.h"

#define LLB_RWR_MAP_SZ (1024)

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct sock_rwr_key);
  __type(value,       struct sock_rwr_action);
  __uint(max_entries, LLB_RWR_MAP_SZ);
} sock_rwr_map SEC(".maps");

SEC("cgroup/connect")
int llb_connect_v4_prog(struct bpf_sock_addr *ska_ctx)
{
  struct bpf_sock *sk;
  struct sock_rwr_key key;
  struct sock_rwr_action *act;
  
  memset(&key, 0, sizeof(key));
  key.vip4 = ska_ctx->user_ip4;
  key.port = ska_ctx->user_port;

  act = bpf_map_lookup_elem(&sock_rwr_map, &key);
  if (!act) {
    return 1;
  }

  //bpf_printk("vip4 0x%x", key.vip4);
  //bpf_printk("port 0x%x", key.port);
  //bpf_printk("rwrport 0x%x", act->rw_port);

  if (ska_ctx->type != SOCK_STREAM && ska_ctx->type != SOCK_DGRAM) {
    return 1;
  }

#ifdef HAVE_LLB_SOCK_RWR_ACTIVE
  struct bpf_sock_tuple t;
  memset(&t, 0, sizeof(t));

  t.ipv4.daddr = ska_ctx->user_ip4;
  t.ipv4.dport = act->rw_port;

  if (ska_ctx->type == SOCK_STREAM) {
    sk = bpf_sk_lookup_tcp(ska_ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
  } else {
    sk = bpf_sk_lookup_udp(ska_ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
  }

  if (!sk) {
    return 1;
  }

  if ((sk->src_ip4 && sk->src_ip4 != t.ipv4.daddr) || sk->src_port != bpf_ntohs(act->rw_port)) {
    bpf_sk_release(sk);
    return 1;
  }
  bpf_sk_release(sk);
#endif


  ska_ctx->user_port = act->rw_port;

  return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
