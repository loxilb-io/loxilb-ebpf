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
  else if ((v1)->u.v.valid) {                                      \
    l += sprintf(fmtstr+l, "%s:0x%x,", kstr, cv((v1)->u.v.valid & (v1)->u.v.val)); \
  }                                                                \
} while(0)

#define PDI_MATCH6_PRINT(v1, kstr, fmtstr, l, cv)                  \
do {                                                               \
  char str[INET6_ADDRSTRLEN];                                      \
  uint8_t zero_addr[16] = { 0 };                                   \
  if (memcmp((v1)->valid, zero_addr, sizeof((v1)->valid))) {       \
    if (inet_ntop(AF_INET6, (v1)->val, str, INET6_ADDRSTRLEN)) {   \
      l += sprintf(fmtstr+l, "%s:%s,", kstr, str);                 \
    }                                                              \
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
  __u32 v6;
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
  uint32_t mark;
  uint16_t polid;
  uint16_t qid;
  uint16_t record;
  uint16_t mirrid;
  uint32_t port;
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

union pdi_key_un {
  struct pdi_key k4;
  struct pdi6_key k6;
};
typedef union pdi_key_un pdi_key_t;

struct pdi_val {
  pdi_key_t val;
  struct pdi_rule *r;
#define PDI_VAL_INACT_TO  (60000000000)
  uint64_t lts;
  UT_hash_handle hh;
};

struct pdi_rule {
  pdi_key_t key;
  struct pdi_data data;
  struct pdi_rule *next;
  struct pdi_val *hash;
};

#define PDI_KEY_EQ(v1, v2)                                        \
  ((PDI_MATCH_ALL(&(v1)->k4.dest, &(v2)->k4.dest)))         &&    \
  ((PDI_MATCH_ALL(&(v1)->k4.source, &(v2)->k4.source)))     &&    \
  ((PDI_RMATCH_ALL(&(v1)->k4.dport, &(v2)->k4.dport)))      &&    \
  ((PDI_RMATCH_ALL(&(v1)->k4.sport, &(v2)->k4.sport)))      &&    \
  ((PDI_MATCH_ALL(&(v1)->k4.inport, &(v2)->k4.inport)))     &&    \
  ((PDI_MATCH_ALL(&(v1)->k4.zone, &(v2)->k4.zone)))         &&    \
  ((PDI_MATCH_ALL(&(v1)->k4.protocol, &(v2)->k4.protocol))) &&    \
  ((PDI_MATCH_ALL(&(v1)->k4.bd, &(v2)->k4.bd)))

#define PDI_PKEY_EQ(v1, v2)                                       \
  (((PDI_MATCH(&(v1)->k4.dest, &(v2)->k4.dest)))            &&    \
  ((PDI_MATCH(&(v1)->k4.source, &(v2)->k4.source)))         &&    \
  ((PDI_RMATCH(&(v1)->k4.dport, &(v2)->k4.dport)))          &&    \
  ((PDI_RMATCH(&(v1)->k4.sport, &(v2)->k4.sport)))          &&    \
  ((PDI_MATCH(&(v1)->k4.inport, &(v2)->k4.inport)))         &&    \
  ((PDI_MATCH(&(v1)->k4.zone, &(v2)->k4.zone)))             &&    \
  ((PDI_MATCH(&(v1)->k4.protocol, &(v2)->k4.protocol)))     &&    \
  ((PDI_MATCH(&(v1)->k4.bd, &(v2)->k4.bd))))

#define PDI_PKEY_NTOH(v1)                                        \
    (v1)->key.k4.dest = htonl((v1)->key.k4.dest);                \
    (v1)->key.k4.source = htonl((v1)->key.k4.source);            \
    (v1)->key.k4.dport = htons((v1)->key.k4.dport);              \
    (v1)->key.k4.dest = htons((v1)->key.k4.sport);               \
    (v1)->key.k4.zone = htons((v1)->key.k4.zone);                \
    (v1)->key.k4.bd = htons((v1)->key.k4.bd);                    \
    (v1)->key.k4.inport = htons((v1)->key.k4.inport);

#define PDI_KEY6_EQ(v1, v2)                                       \
  ((PDI_MATCH6_ALL(&(v1)->k6.dest, &(v2)->k6.dest)))        &&    \
  ((PDI_MATCH6_ALL(&(v1)->k6.source, &(v2)->k6.source)))    &&    \
  ((PDI_RMATCH_ALL(&(v1)->k6.dport, &(v2)->k6.dport)))      &&    \
  ((PDI_RMATCH_ALL(&(v1)->k6.sport, &(v2)->k6.sport)))      &&    \
  ((PDI_MATCH_ALL(&(v1)->k6.inport, &(v2)->k6.inport)))     &&    \
  ((PDI_MATCH_ALL(&(v1)->k6.zone, &(v2)->k6.zone)))         &&    \
  ((PDI_MATCH_ALL(&(v1)->k6.protocol, &(v2)->k6.protocol))) &&    \
  ((PDI_MATCH_ALL(&(v1)->k6.bd, &(v2)->k6.bd)))

#define PDI_PKEY6_EQ(v1, v2)                                      \
  (((PDI_MATCH6(&(v1)->k6.dest, &(v2)->k6.dest)))           &&    \
  ((PDI_MATCH6(&(v1)->k6.source, &(v2)->k6.source)))        &&    \
  ((PDI_RMATCH(&(v1)->k6.dport, &(v2)->k6.dport)))          &&    \
  ((PDI_RMATCH(&(v1)->k6.sport, &(v2)->k6.sport)))          &&    \
  ((PDI_MATCH(&(v1)->k6.inport, &(v2)->k6.inport)))         &&    \
  ((PDI_MATCH(&(v1)->k6.zone, &(v2)->k6.zone)))             &&    \
  ((PDI_MATCH(&(v1)->k6.protocol, &(v2)->k6.protocol)))     &&    \
  ((PDI_MATCH(&(v1)->k6.bd, &(v2)->k6.bd))))

#define PDI_PKEY6_NTOH(v1)                                       \
    (v1)->key.k6.dport = htons((v1)->key.k6.dport);              \
    (v1)->key.k6.dest = htons((v1)->key.k6.sport);               \
    (v1)->key.k6.zone = htons((v1)->key.k6.zone);                \
    (v1)->key.k6.bd = htons((v1)->key.k4.bd);                    \
    (v1)->key.k6.inport = htons((v1)->key.k6.inport);

#define FOR_EACH_PDI_ENT(map, ent) for(ent = map->head; ent; ent = ent->next) 

struct pdi_map *pdi_map_alloc(const char *name, int v6, pdi_add_map_op_t add_map, pdi_del_map_op_t del_map);
int pdi_rule_insert(struct pdi_map *map, struct pdi_rule *new, int *nr);
int pdi_rule_delete(struct pdi_map *map, union pdi_key_un *key, uint32_t pref, int *nr);

#endif
