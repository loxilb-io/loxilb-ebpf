/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>
#include <netdb.h>
#include <poll.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tls.h>
#include <linux/tcp.h>
#include "log.h"
#include "notify.h"

#define MAX_NOTIFY_FDS 65535
#define MAX_NOTIFY_POLL_FDS 8192

typedef struct notify_ent {
  int fd;
  notify_type_t type;
  int poll_slot;
  void *priv;
} notify_ent_t; 

#define NOTI_LOCK(C)    pthread_rwlock_wrlock(&(C)->lock)
#define NOTI_UNLOCK(C)  pthread_rwlock_unlock(&(C)->lock)

typedef struct notify_ctx {
  pthread_rwlock_t lock;
  notify_ent_t earr[MAX_NOTIFY_FDS];
  int n_fds;
  notify_cbs_t cbs;
  int n_pfds;
  struct pollfd pfds[MAX_NOTIFY_POLL_FDS];
} notify_ctx_t ;

static short
notify_conv2poll_events(notify_type_t type)
{
  short events = 0;
  if (type & NOTI_TYPE_IN) {
    events |= POLLIN;
  }
  if (type & NOTI_TYPE_OUT) {
    events |= POLLOUT;
  }
  if (type & NOTI_TYPE_HUP) {
    events |= (POLLRDHUP|POLLHUP);
  }
  if (type & NOTI_TYPE_ERROR) {
    events |= POLLERR;
  }
  return events;
}

static notify_type_t
notify_conv4mpoll_events(short events)
{
  notify_type_t type = 0;

  if (events & POLLIN) {
    type |= NOTI_TYPE_IN;
  }
  if (events & POLLOUT) {
    type |= NOTI_TYPE_OUT;
  }
  if (events & (POLLRDHUP|POLLHUP)) {
    type |= NOTI_TYPE_HUP;
  }
  if (events & (POLLERR|POLLNVAL)) {
    type |=  NOTI_TYPE_ERROR;
  }
  return type;
}

void *
notify_ctx_new(notify_cbs_t *cbs)
{
  notify_ctx_t *nc = calloc(1, sizeof(notify_ctx_t));
  assert(nc);

  if (cbs) {
    nc->cbs.notify = cbs->notify;
    nc->cbs.pdestroy = cbs->pdestroy;
  }

  return nc;
}

int
notify_add_ent(void *ctx, int fd, notify_type_t type, void *priv)
{
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  short events;

  assert(ctx); 

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  events = notify_conv2poll_events(type);
  if (!events) {
    return -EINVAL;
  }

  NOTI_LOCK(nctx); 
  ent = &nctx->earr[fd];
  if (ent->fd > 0) {
    NOTI_UNLOCK(nctx); 
    return -EEXIST;
  }

  ent->type = type;
  ent->fd = fd;
  ent->poll_slot = nctx->n_pfds;
  ent->priv = priv;
  
  nctx->pfds[nctx->n_pfds].fd = fd;
  nctx->pfds[nctx->n_pfds].events = events;

  nctx->n_fds++;
  nctx->n_pfds++;

  NOTI_UNLOCK(nctx); 
  return 0;
}

int
notify_delete_ent__(void *ctx, int fd)
{
  int i = 0;
  notify_ctx_t *nctx = ctx;
  notify_ent_t *ent;
  notify_ent_t *pent;

  assert(ctx); 

  if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
    return -EINVAL;
  }

  ent = &nctx->earr[fd];
  if (ent->fd <= 0) {
    return -ENOENT;
  }

  if (ent->poll_slot < 0) {
    assert(0);
  }

  for (i = ent->poll_slot; i < nctx->n_pfds - 1; i++) {

    pent = NULL;
    if (nctx->pfds[i+1].fd > 0 && nctx->pfds[i+1].fd < MAX_NOTIFY_FDS) {
      pent = &nctx->earr[nctx->pfds[i+1].fd];
    }

    nctx->pfds[i].fd = nctx->pfds[i+1].fd;
    nctx->pfds[i].events = nctx->pfds[i+1].events;

    if (pent) {
      pent->poll_slot = i;
    }
  }

  ent->fd = -1;
  ent->type = 0; 
  ent->poll_slot = -1;
  if (ent->priv) {
    if (nctx->cbs.pdestroy) {
      nctx->cbs.pdestroy(ent->priv);
    }
    ent->priv = NULL;
  }

  nctx->n_fds--;
  nctx->n_pfds--;

  return 0;
}

int
notify_delete_ent(void *ctx, int fd)
{
  int rc;
  notify_ctx_t *nctx = ctx;

  NOTI_LOCK(nctx);
  rc = notify_delete_ent__(ctx, fd);
  NOTI_UNLOCK(nctx);

  return rc;
}

void
notify_run(void *ctx)
{
  int rc = 0;
  int nproc = 0;
  int i = 0;
  int n_pfds = 0;
  void *priv = NULL;
  struct pollfd pfds[MAX_NOTIFY_POLL_FDS];
  notify_ent_t *ent;
  notify_ctx_t *nctx = ctx;

  assert(nctx);

  while(1) {

    nproc = 0;
    /* This is seemingly expensive operation */
    NOTI_LOCK(nctx);
    memcpy(pfds, nctx->pfds, sizeof(pfds));
    n_pfds = nctx->n_pfds;
    NOTI_UNLOCK(nctx);
    
    //printf("n_pfds = %d\n", n_pfds);
    rc = poll(pfds, n_pfds, 500);
    if (rc < 0) {
      perror("poll");
      goto end_of_loop;
    }

    for (i = 0 ; i < n_pfds; i++) {
      int fd = pfds[i].fd;
      notify_type_t type = notify_conv4mpoll_events(pfds[i].revents);
      if (type == 0) {
        continue;
      }

      if (fd <= 0 || fd >= MAX_NOTIFY_FDS) {
        continue;
      }

      NOTI_LOCK(nctx);
      ent = &nctx->earr[fd];
      if (ent->fd <= 0) {
        assert(0); 
      }
      priv = ent->priv;
      NOTI_UNLOCK(nctx);

      if (nctx->cbs.notify) {
        nctx->cbs.notify(fd, type, priv);
      }

      if (type & (NOTI_TYPE_HUP|NOTI_TYPE_ERROR)) {
        log_debug("Closed fd %d", fd);
        notify_delete_ent__(nctx, fd); 
      }
      if (type & NOTI_TYPE_IN) {
        nproc++;
      }
    }

end_of_loop:
    if (nproc <= 0) {
      usleep(200*1000);
    }
  }
}
