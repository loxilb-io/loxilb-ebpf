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
                              .dport = bpf_sops->remote_port,
                              .sport = bpf_sops->local_port,
                              .res = 0
                            };


  bpf_printk("dport %lu sport %lu", key.dport, key.sport);
  etype = bpf_sops->op;

	switch (etype) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		__u32 lport = bpf_sops->local_port;

		if (bpf_sops->local_port == 9090) {
			bpf_sock_hash_update(bpf_sops, &sock_proxy_map, &key, BPF_NOEXIST);
		}
		break;
  }
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
     __u32 rport = bpf_sops->remote_port;

    if (bpf_sops->remote_port == 9090) {
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
