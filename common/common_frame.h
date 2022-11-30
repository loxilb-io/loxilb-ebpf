/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __COMMON_FRAME_H__
#define __COMMON_FRAME_H__

struct mkrt_args {
  uint32_t seq;
  uint8_t fin:1;
  uint8_t syn:1;
  uint8_t rst:1;
  uint8_t psh:1;
  uint8_t ack:1;
  uint8_t urg:1;
  uint8_t res:2;
};

struct mkr_args {
  uint8_t v6;
  uint32_t dip[4];
  uint32_t sip[4];
  uint16_t sport;
  uint16_t dport;
  uint8_t protocol;

  union {
    struct mkrt_args t;
  };
};

int create_raw_tcp(void *packet, size_t *plen, struct mkr_args *args);
int create_xmit_raw_tcp(struct mkr_args *args);

#endif
