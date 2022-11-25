/*
 * Copyright 2022 <Dip J, dipj@netlox.io>
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __PDI_H__
#define __PDI_H__

#include "uthash.h"
#include "common_pdi.h"

#define PDI_MATCH_PRINT(v1, kstr, fmtstr, l, cv)                   \
do {                                                               \
  if ((v1)->valid) {                                               \
    l += sprintf(fmtstr+l, "%s:0x%x,", kstr, cv((v1)->valid & (v1)->val)); \
  }                                                                \
} while(0)

#define PDI_RMATCH_PRINT(v1, kstr, fmtstr, l, cv)                  \
do {                                                               \
  if ((v1)->has_range) {                                           \
    l += sprintf(fmtstr+l, "%s:%d-%d,", kstr,cv((v1)->u.r.min), cv((v1)->u.r.max));   \
  }                                                                \
  else {                                                           \
    l += sprintf(fmtstr+l, "%s:0x%x,", kstr, cv((v1)->u.v.valid & (v1)->u.v.val)); \
  }                                                                \
} while(0)

#define PDI_MAP_NAME_LEN 16
#define PDI_MAP_LOCK(m) pthread_rwlock_wrlock(&m->lock)
#define PDI MAP_RLOCK(m) pthread_rwlock_rdlock(&m->lock)
#define PDI_MAP_ULOCK(m) pthread_rwlock_unlock(&m->lock)

struct pdi_map {
  char name[PDI_MAP_NAME_LEN];
  pthread_rwlock_t lock;
  __u32 nr;
  struct pdi_rule *head;
  int (*pdi_add_map_em)(void *key, void *val, size_t sz);
  int (*pdi_del_map_em)(void *key);
};

typedef int (*pdi_add_map_op_t)(void *key, void *val, size_t sz);
typedef int (*pdi_del_map_op_t)(void *key);

struct pdi_gen_key {
    PDI_TYPEDEF(32)    dest;
    PDI_TYPEDEF(32)    source;
    PDI_TYPEDEF_R(16)  dport;
    PDI_TYPEDEF_R(16)  sport;
    PDI_TYPEDEF(16)    inport;
    PDI_TYPEDEF(8)     protocol;
    PDI_TYPEDEF(8)     dir;
    PDI_TYPEDEF(32)    ident;
};

#define PDI_SET_QFI    0x1
#define PDI_SET_POL    0x2
#define PDI_SET_GBR    0x4
#define PDI_SET_DROP   0x8
#define PDI_SET_MIRR   0x10
#define PDI_SET_FWD    0x20
#define PDI_SET_TRAP   0x40
#define PDI_SET_RDR    0x80

struct pdi_opts {
  uint32_t qfi; 
  uint16_t polid;
  uint16_t qid;
  uint16_t mirrid;
  uint16_t res;
  uint16_t port;
  uint32_t teid;
};

struct pdi_data {
  uint32_t pref;
  uint32_t rid;
  uint32_t op;
  struct pdi_opts opts;
};

struct pdi_stats {
  uint64_t bytes;
  uint64_t packets;
};

struct pdi_val {
  struct pdi_key val;
  struct pdi_rule *r;
#define PDI_VAL_INACT_TO  (60000000000)
  uint64_t lts;
  UT_hash_handle hh;
};

struct pdi_rule {
  struct pdi_key key;
  struct pdi_data data;
  struct pdi_rule *next;
  struct pdi_val *hash;
};

#define PDI_KEY_EQ(v1, v2)                                  \
  ((PDI_MATCH_ALL(&(v1)->dest, &(v2)->dest)))         &&    \
  ((PDI_MATCH_ALL(&(v1)->source, &(v2)->source)))     &&    \
  ((PDI_RMATCH_ALL(&(v1)->dport, &(v2)->dport)))      &&    \
  ((PDI_RMATCH_ALL(&(v1)->sport, &(v2)->sport)))      &&    \
  ((PDI_MATCH_ALL(&(v1)->inport, &(v2)->inport)))     &&    \
  ((PDI_MATCH_ALL(&(v1)->zone, &(v2)->zone)))         &&    \
  ((PDI_MATCH_ALL(&(v1)->protocol, &(v2)->protocol))) &&    \
  ((PDI_MATCH_ALL(&(v1)->bd, &(v2)->bd)))

#define PDI_PKEY_EQ(v1, v2)                             \
  (((PDI_MATCH(&(v1)->dest, &(v2)->dest)))        &&    \
  ((PDI_MATCH(&(v1)->source, &(v2)->source)))     &&    \
  ((PDI_RMATCH(&(v1)->dport, &(v2)->dport)))      &&    \
  ((PDI_RMATCH(&(v1)->sport, &(v2)->sport)))      &&    \
  ((PDI_MATCH(&(v1)->inport, &(v2)->inport)))     &&    \
  ((PDI_MATCH(&(v1)->zone, &(v2)->zone)))         &&    \
  ((PDI_MATCH(&(v1)->protocol, &(v2)->protocol))) &&    \
  ((PDI_MATCH(&(v1)->bd, &(v2)->bd))))

#define PDI_PKEY_NTOH(v1)                          \
    (v1)->dest = htonl((v1)->dest);                \
    (v1)->source = htonl((v1)->source);            \
    (v1)->dport = htons((v1)->dport);              \
    (v1)->dest = htons((v1)->sport);               \
    (v1)->zone = htons((v1)->zone);                \
    (v1)->bd = htons((v1)->bd);                    \
    (v1)->inport = htons((v1)->inport);

#define FOR_EACH_PDI_ENT(map, ent) for(ent = map->head; ent; ent = ent->next) 

struct pdi_map *pdi_map_alloc(const char *name, pdi_add_map_op_t add_map, pdi_del_map_op_t del_map);
int pdi_rule_insert(struct pdi_map *map, struct pdi_rule *new, int *nr);
int pdi_rule_delete(struct pdi_map *map, struct pdi_key *key, uint32_t pref, int *nr);

#endif
