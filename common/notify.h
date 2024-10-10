/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __NOTIFY_H__
#define __NOTIFY_H__

typedef enum {
  NOTI_TYPE_IN     = 0x1 << 0,
  NOTI_TYPE_HUP    = 0x1 << 1,
  NOTI_TYPE_OUT    = 0x1 << 2,
  NOTI_TYPE_ERROR  = 0x1 << 3,
  NOTI_TYPE_SHUT   = 0x1 << 4,
} notify_type_t;

typedef struct notify_cbs {
  int (*notify)(int fd, notify_type_t type, void *priv);
  void (*pdestroy)(void *priv);
} notify_cbs_t ;

int notify_check_slot(void *ctx, int fd);
int notify_delete_ent(void *ctx, int fd, int evict);
int notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv);
int notify_start(void *ctx);
void *notify_ctx_new(notify_cbs_t *cbs, int n_thrs);

#endif
