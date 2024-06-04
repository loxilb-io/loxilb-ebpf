/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_H__
#define __SOCKPROXY_H__

typedef enum {
  PROXY_SOCK_LISTEN = 1,
  PROXY_SOCK_ACTIVE,
} proxy_socktype_t;

struct proxy_cache {
  void *cache;
  uint16_t off;
  size_t len;
  struct proxy_cache *next;
  uint8_t data[0];
};
typedef struct proxy_cache proxy_cache_t;

struct proxy_fd_ent {
  int fd;
#define MAX_PROXY_EP 16
  int rfd[MAX_PROXY_EP];
  int n_rfd;
  int mode;
  int lsel;
  int protocol;
  int seltype;
  int odir;
  proxy_socktype_t stype;
  proxy_cache_t *cache_head;
};
typedef struct proxy_fd_ent proxy_fd_ent_t;

struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
typedef struct proxy_ent proxy_ent_t;

struct proxy_val {
  uint32_t _id;
#define PROXY_MODE_DFL 0
#define PROXY_MODE_ALL 1
  int proxy_mode;
#define PROXY_SEL_RR    0
#define PROXY_SEL_HASH  1
#define PROXY_SEL_N2    2
  int select;
  int main_fd;
  int ep_sel;
  int n_eps;
  proxy_ent_t eps[MAX_PROXY_EP];
};
typedef struct proxy_val proxy_val_t;

typedef int (*sockmap_cb_t)(struct llb_sockmap_key *key, int fd, int doadd);
int proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol,
                  uint32_t *epip, uint16_t *epport, uint8_t *epprotocol);
int proxy_add_entry(struct proxy_ent *new_ent, struct proxy_val *val);
int proxy_delete_entry(struct proxy_ent *ent);
void proxy_dump_entry(void);
int proxy_main(sockmap_cb_t cb);

#endif
