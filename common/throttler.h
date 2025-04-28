/*
 * Copyright (c) 2023-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __THROTTLER_H__
#define __THROTTLER_H__

struct throttler {
  pthread_rwlock_t mutex;
  uint64_t curr_tok;
  uint64_t toks_per_sec;
  unsigned long long last_ts;
};

int init_throttler(struct throttler *l, int tps);
int do_throttle(struct throttler *l);

#endif
