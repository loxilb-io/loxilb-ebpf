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
#include "../common/llb_sockmap.h"

SEC("sk_msg")
int llb_sockmap_dir(struct sk_msg_md *mmd)
{
  struct llb_sockmap_key key = { .dip = mmd->local_ip4,
                                 .sip = mmd->remote_ip4,
                                 .dport = bpf_htonl(mmd->local_port) >> 16,
                                 .sport = mmd->remote_port >> 16,
                               };

  if (key.sport == bpf_htons(9090)) {
    key.dip = 0;
    key.sip = 0;
    key.dport = 0;
  } else if (key.dport == bpf_htons(9090)) {
    key.dip = 0;
    key.sip = 0;
    key.sport = 0;
  }

  bpf_printk("sockdir: sport %lu dport %lu", bpf_ntohs(key.sport), bpf_ntohs(key.dport));
  if (key.sport == bpf_htons(9090) ||
      key.dport == bpf_htons(9090)) { 
    bpf_msg_redirect_hash(mmd, &sock_proxy_map, &key, BPF_F_INGRESS);
	}

  return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
