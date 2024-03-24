/* 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LLB_RWR_MAP_SZ (1024)

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

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct sock_rwr_key);
  __type(value,       struct sock_rwr_action);
  __uint(max_entries, LLB_RWR_MAP_SZ);
} sock_rwr_map SEC(".maps");

SEC("cgroup/connect")
int llb_connect_v4_prog(struct bpf_sock_addr *ska_ctx)
{
  struct sockaddr_in sa;
  struct bpf_sock *sk;
  struct bpf_sock_tuple t;
  struct sock_rwr_key key;
  struct sock_rwr_action *act;
  
  memset(&key, 0, sizeof(key));
  key.vip4 = ska_ctx->user_ip4;
  key.port = ska_ctx->user_port;

  bpf_printk("vip4 0x%x", key.vip4);
  bpf_printk("port 0x%x", key.port);

  act = bpf_map_lookup_elem(&sock_rwr_map, &key);
  if (!act) {
    return 0;
  }

  memset(&t, 0, sizeof(t));

  t.ipv4.daddr = ska_ctx->user_ip4;
  t.ipv4.dport = act->rw_port;

  if (ska_ctx->type != SOCK_STREAM && ska_ctx->type != SOCK_DGRAM) {
    return 0;
  } else if (ska_ctx->type == SOCK_STREAM) {
    sk = bpf_sk_lookup_tcp(ska_ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
  } else {
    sk = bpf_sk_lookup_udp(ska_ctx, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
  }

  if (!sk) {
    return 0;
  }

  if (sk->src_ip4 != t.ipv4.daddr || sk->src_port != bpf_ntohs(act->rw_port)) {
    bpf_sk_release(sk);
    return 0;
  }

  bpf_sk_release(sk);

  ska_ctx->user_port = act->rw_port;

  return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
