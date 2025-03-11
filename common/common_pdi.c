/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include "pdi.h"

struct pdi_map *
pdi_map_alloc(const char *name, int v6, pdi_add_map_op_t add_map, pdi_del_map_op_t del_map)
{
  struct pdi_map *map = calloc(1, sizeof(struct pdi_map));

  if (name) {
    strncpy(map->name, name, PDI_MAP_NAME_LEN);
    map->name[PDI_MAP_NAME_LEN-1] = '\0'; 
  } else {
    strncpy(map->name, "default", PDI_MAP_NAME_LEN);
  }
  map->v6 = v6 ? 1 : 0;
  map->pdi_add_map_em = add_map;
  map->pdi_del_map_em = del_map;

  return map;
}

void
pdi_key2str(struct pdi_map *map, pdi_key_t *key, char *fstr)
{
  int l = 0;

  if (map->v6 == 0) {
    PDI_MATCH_PRINT(&key->k4.dest, "dest", fstr, l, none);
    PDI_MATCH_PRINT(&key->k4.source, "source", fstr, l, none);
    PDI_RMATCH_PRINT(&key->k4.dport, "dport", fstr, l, none);
    PDI_RMATCH_PRINT(&key->k4.sport, "sport", fstr, l, none);
    PDI_MATCH_PRINT(&key->k4.inport, "inport", fstr, l, none);
    PDI_MATCH_PRINT(&key->k4.protocol, "prot", fstr, l, none);
    PDI_MATCH_PRINT(&key->k4.zone, "zone", fstr, l, none);
    PDI_MATCH_PRINT(&key->k4.bd, "bd", fstr, l, none);
  } else {
    PDI_MATCH6_PRINT(&key->k6.dest, "dest6", fstr, l, none);
    PDI_MATCH6_PRINT(&key->k6.source, "source6", fstr, l, none);
    PDI_RMATCH_PRINT(&key->k6.dport, "dport", fstr, l, none);
    PDI_RMATCH_PRINT(&key->k6.sport, "sport", fstr, l, none);
    PDI_MATCH_PRINT(&key->k6.inport, "inport", fstr, l, none);
    PDI_MATCH_PRINT(&key->k6.protocol, "prot", fstr, l, none);
    PDI_MATCH_PRINT(&key->k6.zone, "zone", fstr, l, none);
    PDI_MATCH_PRINT(&key->k6.bd, "bd", fstr, l, none);
  }
}

void
pdi_rule2str(struct pdi_map *map, struct pdi_rule *node)
{
  char fmtstr[1000] = { 0 };

  if (1) {
    pdi_key2str(map, &node->key, fmtstr);
    printf("(%s)%d\n", fmtstr, node->data.pref);
  }
}

void
pdi_rules2str(struct pdi_map *map)
{
  struct pdi_rule *node = map->head;

  printf("#### Rules ####\n");
  while (node) {
    pdi_rule2str(map, node);
    node = node->next;
  }
  printf("##############\n");
}

int
pdi_rule_insert(struct pdi_map *map, struct pdi_rule *new, int *nr)
{
  struct pdi_rule *prev =  NULL;
  struct pdi_rule *node;
  uint32_t pref = new->data.pref;

  if (nr) *nr = 0;

  PDI_MAP_LOCK(map);

  node = map->head;

  while (node) {
    if (pref > node->data.pref) {
      if (prev) {
        prev->next = new;
        new->next = node;
      } else {
        map->head = new;
        new->next = node;
      }

      map->nr++;
      PDI_MAP_ULOCK(map);
      return 0;
    }

    if (pref == node->data.pref)  {
      int equal = 0;
      if (map->v6) {
        equal = PDI_KEY6_EQ(&new->key, &node->key);
      } else {
        equal = PDI_KEY_EQ(&new->key, &node->key);
      }
      if (equal) {
        PDI_MAP_ULOCK(map);
        return -EEXIST;
      } 
    }
    prev = node;
    node = node->next;
    if (nr) {
      *nr = *nr + 1;;
    }
  }

  if (prev) {
    prev->next = new;
    new->next = node;
  } else {
    map->head = new;
    new->next = node;
  }
  map->nr++;

  PDI_MAP_ULOCK(map);

  return 0;
}

struct pdi_rule *
pdi_rule_delete__(struct pdi_map *map, union pdi_key_un *key, uint32_t pref, int *nr)
{
  struct pdi_rule *prev =  NULL;
  struct pdi_rule *node;

  node = map->head;

  while (node) {
    if (pref == node->data.pref)  {
      int equal = 0;
      if (map->v6) {
        equal = PDI_KEY6_EQ(key, &node->key);
      } else {
        equal = PDI_KEY_EQ(key, &node->key);
      }
      if (equal) {
        if (prev) {
          prev->next = node->next;
        } else {
          map->head = node->next;
        }
        map->nr--;
        return node;
      } 
    }
    prev = node;
    node = node->next;
    if (nr) {
      *nr = *nr + 1;
    }
  }

  return NULL;
}

int
pdi_rule_delete(struct pdi_map *map, union pdi_key_un *key, uint32_t pref, int *nr)
{
  struct pdi_rule *node = NULL;
  struct pdi_val *val, *tmp;

  PDI_MAP_LOCK(map);

  node = pdi_rule_delete__(map, key, pref, nr);
  if (node != NULL) {
    //pdi_rule2str(node);
    HASH_ITER(hh, node->hash, val, tmp) {
      HASH_DEL(node->hash, val);
      if (map->pdi_del_map_em) {
        map->pdi_del_map_em(&val->val);
      }
      free(val);
    }
    free(node);
    PDI_MAP_ULOCK(map);

    return 0;
  }

  PDI_MAP_ULOCK(map);
  return -1;
}

struct pdi_rule *
pdi_rule_get__(struct pdi_map *map, union pdi_key_un *val)
{
  struct pdi_rule *node = map->head;

  while (node) {
    //pdi_rule2str(node);
    if (PDI_PKEY_EQ(val, &node->key)) {
      return node;
    } 
    node = node->next;
  }
  return NULL;
}

int
pdi_add_val(struct pdi_map *map, union pdi_key_un *kval)
{
  struct pdi_val *hval = NULL;
  struct pdi_rule *rule = NULL;

  PDI_MAP_LOCK(map);

  rule = pdi_rule_get__(map, kval);
  if (rule != NULL) {
    pdi_rule2str(map, rule);

    HASH_FIND(hh, rule->hash, kval, sizeof(union pdi_key_un), hval);
    if (hval) {
      if (map->pdi_add_map_em) {
        map->pdi_add_map_em(kval, &rule->data, sizeof(rule->data));
      }
      PDI_MAP_ULOCK(map);
      return -EEXIST;
    }

    hval = calloc(1, sizeof(*hval));
    memcpy(&hval->val, kval, sizeof(*kval));
    hval->r = rule;
    HASH_ADD(hh, rule->hash, val, sizeof(union pdi_key_un), hval);
    PDI_MAP_ULOCK(map);
    return 0;
  }

  PDI_MAP_ULOCK(map);

  return -1;
}

int
pdi_del_val(struct pdi_map *map, union pdi_key_un *kval)
{
  struct pdi_val *hval = NULL;
  struct pdi_rule *rule = NULL;

  PDI_MAP_LOCK(map);

  rule = pdi_rule_get__(map, kval);
  if (rule != NULL) {
    pdi_rule2str(map, rule);

    HASH_FIND(hh, rule->hash, kval, sizeof(union pdi_key_un), hval);
    if (hval == NULL) {
      PDI_MAP_ULOCK(map);
      return -EINVAL;
    }

    HASH_DEL(rule->hash, hval);
    PDI_MAP_ULOCK(map);
    return 0;
  }

  PDI_MAP_ULOCK(map);
  return -1;
}

static int
pdi_val_expired(struct pdi_val *v)
{
  // TODO 
  return 0;
}

void
pdi_map_run(struct pdi_map *map)
{
  struct pdi_rule *node;
  struct pdi_val *val, *tmp;
  char fmtstr[512] = { 0 };

  PDI_MAP_LOCK(map);

  node = map->head;

  while (node) {
    HASH_ITER(hh, node->hash, val, tmp) {
      if (pdi_val_expired(val)) {
        HASH_DEL(node->hash, val);
        if (map->pdi_del_map_em) {
          map->pdi_del_map_em(&val->val);
        }
        pdi_key2str(map, &val->val, fmtstr);
        free(val);
      }
    }
    node = node->next;
  }
  PDI_MAP_ULOCK(map);
}

int
pdi_unit_test(void)
{
  struct pdi_map *map;
  struct pdi_map *map6;
  int r = 0;

  map = pdi_map_alloc("ufw4", 0, NULL, NULL);
  map6 = pdi_map_alloc("ufw6", 1, NULL, NULL);

  struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
  if (new) {
    PDI_MATCH_INIT(&new->key.k4.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_RMATCH_INIT(&new->key.k4.dport, 1, 100, 200);
    r = pdi_rule_insert(map, new, NULL);
    if (r != 0) {
      printf("Insert fail1\n");
      exit(0);
    }
  }

  struct pdi_rule *new1 = calloc(1, sizeof(struct pdi_rule));
  if (new1) {
    memcpy(new1, new, sizeof(*new));
    new1->data.pref = 100;
    r = pdi_rule_insert(map, new1, NULL);
    if (r != 0) {
     printf("Insert fail2\n");
     exit(0);
    }
  }

  struct pdi_rule *new2 = calloc(1, sizeof(struct pdi_rule));
  if (new2) {
    PDI_MATCH_INIT(&new2->key.k4.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_RMATCH_INIT(&new2->key.k4.dport, 0, 100, 0xffff);
    r = pdi_rule_insert(map, new2, NULL);
    if (r != 0) {
      printf("Insert fail3\n");
      exit(0);
    }

    r = pdi_rule_insert(map, new2, NULL);
    if (r == 0) {
      printf("Insert fail4\n");
      exit(0);
    }
  }

  if (pdi_rule_delete(map, &new1->key, 100, NULL) != 0) {
    // Free //
    printf("Delete fail4\n");
    exit(0);
  }

  struct pdi_rule *new4 = calloc(1, sizeof(struct pdi_rule));
  if (new4) {
    PDI_MATCH_INIT(&new4->key.k4.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_MATCH_INIT(&new4->key.k4.source, 0x0b0b0b00, 0xffffff00);
    PDI_RMATCH_INIT(&new4->key.k4.dport, 1, 500, 600);
    PDI_RMATCH_INIT(&new4->key.k4.sport, 1, 600, 700);
    r = pdi_rule_insert(map, new4, NULL);
    if (r != 0) {
      printf("Insert fail1\n");
      exit(0);
    }
  }

  pdi_rules2str(map);

  if (1) {
    pdi_key_t key =  { 0 } ;
    PDI_VAL_INIT(&key.k4.source, 0x0b0b0b0b);
    PDI_VAL_INIT(&key.k4.dest, 0x0a0a0a0a);
    PDI_RVAL_INIT(&key.k4.dport, 501);
    PDI_RVAL_INIT(&key.k4.sport, 501);
    if (pdi_add_val(map, &key) != 0) {
      printf("Failed to add pdi val1\n");
    }
  }

  if (1) {
    pdi_key_t key =  { 0 } ;
    PDI_VAL_INIT(&key.k4.source, 0x0b0b0b0b);
    PDI_VAL_INIT(&key.k4.dest, 0x0a0a0a0a);
    PDI_RVAL_INIT(&key.k4.dport, 502);
    PDI_RVAL_INIT(&key.k4.sport, 502);
    if (pdi_add_val(map, &key) != 0) {
      printf("Failed to add pdi val2\n");
    }
  }

  if (pdi_rule_delete(map, &new4->key, 0, NULL) != 0) {
     printf("Failed delete--%d\n", __LINE__);
  }

  struct pdi_rule *new6 = calloc(1, sizeof(struct pdi_rule));
  if (new) {
    struct in6_addr addr6;
    struct in6_addr net6;
    inet_pton(AF_INET6, "2001::1234", &addr6);
    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &net6);
    PDI_MATCH6_INIT(&new6->key.k6.dest, &addr6.s6_addr, &net6.s6_addr);
    PDI_RMATCH_INIT(&new6->key.k6.dport, 1, 100, 200);
    r = pdi_rule_insert(map6, new6, NULL);
    if (r != 0) {
      printf("Insert fail1\n");
      exit(0);
    }

    r = pdi_rule_insert(map6, new6, NULL);
    if (r == 0) {
      printf("Insert fail1\n");
      exit(0);
    }

  }

  pdi_rules2str(map6);

  if (1) {
    pdi_key_t key =  { 0 } ;
    struct in6_addr addr6;
    inet_pton(AF_INET6, "2001::1234", &addr6);
    PDI_VAL6_INIT(&key.k6.dest, &addr6.s6_addr);
    PDI_RVAL_INIT(&key.k6.dport, 102);
    if (pdi_add_val(map6, &key) != 0) {
      printf("Failed to add pdi val2\n");
      exit(0);
    }
  }

  if (pdi_rule_delete(map6, &new6->key, 0, NULL) != 0) {
    printf("Failed delete--%d\n", __LINE__);
    exit(0);
  }

  return 0;
}
