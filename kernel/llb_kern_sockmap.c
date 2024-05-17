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

SEC("sockops")
int llb_setup_sockmap(struct bpf_sock_ops *bpf_sops)
{
	int etype, err;
  struct llb_sockmap_key key = { .dip = bpf_sops->remote_ip4,
                                 .sip = bpf_sops->local_ip4,
                                 .dport = bpf_sops->remote_port >> 16,
                                 .sport = bpf_htonl(bpf_sops->local_port) >> 16,
                                 .res = 0
                               };

  etype = bpf_sops->op;

	switch (etype) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
    bpf_printk("passive:lport %lu ", bpf_ntohs(key.sport));

		if (key.sport == bpf_htons(9090)) {
			bpf_sock_hash_update(bpf_sops, &sock_proxy_map, &key, BPF_NOEXIST);
		}
		break;
  }
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
    bpf_printk("passive:dport %lu ", bpf_ntohs(key.dport));

    if (key.dport == bpf_htons(9090)) {
      bpf_sock_hash_update(bpf_sops, &sock_proxy_map, &key, BPF_NOEXIST);
    }
    break;
  }
  default:
    break;
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
