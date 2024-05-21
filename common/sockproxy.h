/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_H__
#define __SOCKPROXY_H__

struct llb_sockmap_key {
  uint32_t dip;
  uint32_t sip;
  uint32_t dport;
  uint32_t sport;
};

struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint16_t inv;
};

#define MAX_PROXY_EP 16

struct proxy_val {
  uint32_t _id;
  int sel_on;
  int main_fd;
  int ep_sel;
  int n_eps;
  struct proxy_ent eps[MAX_PROXY_EP];
};

int sockproxy_find_endpoint(uint32_t xip, uint16_t xport, uint32_t *epip, uint16_t *epport);
int sockproxy_add_entry(struct proxy_ent *new_ent, struct proxy_val *val);
int sockproxy_delete_entry(struct proxy_ent *ent);
void sockproxy_dump_entry(void);
int sockproxy_main();

#endif
