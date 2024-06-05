/*
 * Copyright (c) 2024 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
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
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/tls.h>
#include <linux/tcp.h>
#include "log.h"
#include "ngap.h"
#include "ngap_helper.h"

#define IE_LOOP_FOR_ID(M, IE,  __ID)                              \
do {                                                              \
  int i = 0;                                                      \
  for (i = 0; i < (M)->protocolIEs.list.count && !(__ID); i++) {  \
    (IE) = (M)->protocolIEs.list.array[i];                        \
    switch ((IE)->id) {                                           \
    case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:                    \
      __ID = (IE)->value.choice.RAN_UE_NGAP_ID;                   \
      break;                                                      \
    default:                                                      \
      break;                                                      \
    }                                                             \
  }                                                               \
} while(0)

int
ngap_proto_unmarshal_ueid(void *msg, size_t len, uint32_t *identifier)
{
  struct NGAP_NGAP_PDU m = { 0 };
  struct NGAP_NGAP_PDU *pdu = &m;
  NGAP_InitiatingMessage_t *im;
  unsigned long id = 0;
  asn_dec_rval_t rc;

  memset(&pdu, 0, sizeof(pdu));
  memset(&rc, 0, sizeof(rc));

  rc = aper_decode(NULL, &asn_DEF_NGAP_NGAP_PDU, (void **)&pdu, msg, len, 0, 0);
  if (rc.code != RC_OK) {
    return -EINVAL;
  }

  *identifier = 0;

  switch (pdu->present) {
  case NGAP_NGAP_PDU_PR_initiatingMessage:
  case NGAP_NGAP_PDU_PR_successfulOutcome:
  case NGAP_NGAP_PDU_PR_unsuccessfulOutcome:
    im = pdu->choice.initiatingMessage;
    switch (im->procedureCode) {
    case NGAP_ProcedureCode_id_NGSetup:
    case NGAP_ProcedureCode_id_NGReset:
      /* Non-NAS messages */
      break;
    default: {
      NGAP_InitialUEMessage_t *iuem = &im->value.choice.InitialUEMessage;
      NGAP_InitialUEMessage_IEs_t *ies;
      IE_LOOP_FOR_ID(iuem, ies, id);
      //log_debug("Procedure %d -- id 0x%x", im->procedureCode, id);
      break;
      }
    }
    break;
  default:
    break;
  }

  ASN_STRUCT_RESET(asn_DEF_NGAP_NGAP_PDU, pdu);
  if (id == 0) {
    return -1;
  }
  *identifier = id;
  return 0;
}

int
ngap_proto_epsel_helper(void *msg, size_t len, int max_ep)
{
  uint32_t hash;
  uint32_t id;

  if (ngap_proto_unmarshal_ueid(msg, len, &id) < 0) {
    return -1;
  }

  hash = (id >> 16 & 0xffff) ^ (id & 0xffff);
  log_debug("id = 0x%x hash = 0x%x", id, hash);
  return hash % max_ep;
}
