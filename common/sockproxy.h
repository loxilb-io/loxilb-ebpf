/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_H__
#define __SOCKPROXY_H__

#include "llhttp.h"

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
#define MAX_PROXY_EP LLB_MAX_NXFRMS
  int rfd[MAX_PROXY_EP];
  struct proxy_fd_ent *rfd_ent[MAX_PROXY_EP];
  int n_rfd;
  int mode;
  int ep_num;
  int lsel;
  int protocol;
  int seltype;
  int odir;
  int ssl_err;
  uint32_t _id;
  proxy_socktype_t stype;
  proxy_cache_t *cache_head;
  struct proxy_fd_ent *next;
  void *head;
  void *ssl;
  void *epv;
  uint64_t nrb;
  uint64_t nrp;
  uint64_t ntb;
  uint64_t ntp;
  size_t rcv_off;
  int http_pok;
  int http_hok;
  int http_hvok;
  char host_url[256];
  llhttp_t parser;
  llhttp_settings_t settings;
#define SP_SOCK_MSG_LEN 8192
  uint8_t rcvbuf[SP_SOCK_MSG_LEN];
};
typedef struct proxy_fd_ent proxy_fd_ent_t;

#define PROXY_MODE_DFL 0
#define PROXY_MODE_ALL 1

#define PROXY_SEL_RR    0
#define PROXY_SEL_HASH  1
#define PROXY_SEL_N2    2

struct proxy_ent {
  uint32_t xip;
  uint16_t xport;
  uint8_t inv;
  uint8_t protocol;
};
typedef struct proxy_ent proxy_ent_t;

struct proxy_arg {
  char host_url[256];
  uint32_t _id;
  int have_ssl;
  int have_epssl;
  int proxy_mode;
  int select;
  int n_eps;
  int have_ssl;
  void *ssl_ctx;
  struct proxy_fd_ent *fdlist;
  proxy_ent_t eps[MAX_PROXY_EP];
};
typedef struct proxy_arg proxy_arg_t;

typedef int (*sockmap_cb_t)(struct llb_sockmap_key *key, int fd, int doadd);
typedef void (*proxy_info_cb_t)(struct dp_proxy_ct_ent *pct);
int proxy_find_ep(uint32_t xip, uint16_t xport, uint8_t protocol,
                  uint32_t *epip, uint16_t *epport, uint8_t *epprotocol);
int proxy_add_entry(struct proxy_ent *new_ent, struct proxy_arg *arg);
int proxy_delete_entry(struct proxy_ent *ent, struct proxy_arg *arg);
void proxy_dump_entry(proxy_info_cb_t);
void proxy_get_entry_stats(uint32_t id, int epid, uint64_t *p, uint64_t *b);
int proxy_main(sockmap_cb_t cb);

#endif
