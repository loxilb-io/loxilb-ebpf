/*
 *  llb_sockmap.h: LoxiLB sockmap definitions 
 *  Copyright (C) 2024,  NetLOX <www.netlox.io>
 * 
 *  SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) 
 */
#ifndef __LLB_SOCKMAP_H__
#define __LLB_SOCKMAP_H__

struct sock_proxy_map_d {
  __uint(type,        BPF_MAP_TYPE_SOCKHASH);
  __type(key,         struct llb_sockmap_key);
  __type(value,       int);
  __uint(max_entries, LLB_SOCK_MAP_SZ);
} sock_proxy_map SEC(".maps");

#endif
