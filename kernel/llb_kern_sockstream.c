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

#ifndef HAVE_SOCKOPS
struct {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       int);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map2 SEC(".maps");
#else
#define sock_proxy_map2 sock_proxy_map
#endif

SEC("sk_skb/stream_parser")
int llb_sock_parser(struct __sk_buff *skb)
{
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int llb_sock_verdict(struct __sk_buff *skb)
{
  struct llb_sockmap_key key = { .dip = skb->remote_ip4,
                                 .sip = skb->local_ip4,
                                 .dport = skb->remote_port,
                                 .sport = bpf_ntohl(skb->local_port)
                                };

  bpf_printk("sockstream: family %d", skb->family);
  bpf_printk("sockstream: dip 0x%lx sip 0x%lx", bpf_ntohl(skb->remote_ip4), bpf_ntohl(skb->local_ip4));
  bpf_printk("sockstream: dportt %lu sport %lu", bpf_ntohl(skb->remote_port), (skb->local_port));

  return bpf_sk_redirect_hash(skb, &sock_proxy_map2,  &key, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
