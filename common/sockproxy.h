/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_H__
#define __SOCKPROXY_H__

struct proxy_cache {
  void *cache;
  uint16_t off;
  size_t len;
  struct proxy_cache *next;
  uint8_t data[0];
};

struct proxy_fd_ent {
  int fd;
  int rfd;
  int mode;
  int protocol;
  struct proxy_cache *cache_head;
};

struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};

#define MAX_PROXY_EP 16

struct proxy_val {
  uint32_t _id;
  int sel_type;
  int main_fd;
  int ep_sel;
  int n_eps;
  struct proxy_ent eps[MAX_PROXY_EP];
};

typedef int (*sockmap_cb_t)(struct llb_sockmap_key *key, int fd, int doadd);

int sockproxy_find_endpoint(uint32_t xip, uint16_t xport, uint8_t protocol,
                            uint32_t *epip, uint16_t *epport, uint8_t *epprotocol);
int sockproxy_add_entry(struct proxy_ent *new_ent, struct proxy_val *val);
int sockproxy_delete_entry(struct proxy_ent *ent);
void sockproxy_dump_entry(void);
int sockproxy_main(sockmap_cb_t cb);

#endif
