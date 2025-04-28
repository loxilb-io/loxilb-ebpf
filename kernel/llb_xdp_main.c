/*
 * llb_xdp_main.c: LoxiLB XDP Main
 * Copyright (c) 2022-2025 LoxiLB Authors
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "llb_kern_entry.c"

char _license[] SEC("license") = "Dual BSD/GPL";
