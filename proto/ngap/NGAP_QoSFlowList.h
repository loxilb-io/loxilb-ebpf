/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_QoSFlowList_H_
#define	_NGAP_QoSFlowList_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_QosFlowIdentifier.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_QoSFlowList */
typedef struct NGAP_QoSFlowList {
	A_SEQUENCE_OF(NGAP_QosFlowIdentifier_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_QoSFlowList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_QoSFlowList;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_QoSFlowList_H_ */
#include <asn_internal.h>
