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

#define LLB_SOCK_MAP_SZ (1024)

struct llb_sock_key {
  __be32 dip;
  __be32 sip;
  __be16 dport;
  __be16 sport;
  __be32 res;
};

struct {
  __uint(type,        BPF_MAP_TYPE_SOCKMAP);
  __type(key,         int);
  __type(value,       int);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map SEC(".maps");

SEC("sock_parser")
int llb_sock_parser(struct __sk_buff *skb)
{
  return skb->len;
}

SEC("sock_verdict")
int llb_sock_verdict(struct __sk_buff *skb)
{
  struct llb_sock_key key = { .dip = skb->remote_ip4,
                              .sip = skb->local_ip4,
                              .dport = skb->remote_port,
                              .sport = skb->local_port,
                              .res = 0
                            };

  return bpf_sk_redirect_hash(skb, &sock_proxy_map,  &key, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
