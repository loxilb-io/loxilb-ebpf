/*
 * Copyright (c) 2023 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "throttler.h"

static unsigned long long
get_curr_usecs(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((unsigned long long)ts.tv_sec * 1000000UL) + ts.tv_nsec/1000;
}

int init_throttler(struct throttler *l, int tps)
{
  memset(l, 0, sizeof(*l));
  l->curr_tok = 1000000UL;
  l->toks_per_sec = tps*1000000UL;
  l->last_ts = get_curr_usecs();
  pthread_rwlock_init(&l->mutex, NULL);

  return 0;
}

int do_throttle(struct throttler *l)
{
  unsigned long long cts = get_curr_usecs();
  double diff;
  double toks;

  pthread_rwlock_wrlock(&l->mutex);

  diff = ((double)(cts) - (double)(l->last_ts))/1000000UL;
  toks = (diff * l->toks_per_sec) + l->curr_tok;
  if (toks >= 1000000UL) {
    toks -= 1000000UL;
    l->curr_tok = toks;
    l->last_ts = cts;
    pthread_rwlock_unlock(&l->mutex);
    return 0;
  }

  l->curr_tok = toks;
  l->last_ts = cts;

  pthread_rwlock_unlock(&l->mutex);

  return 1;
}
