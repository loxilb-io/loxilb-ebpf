/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_FromEUTRANtoNGRAN_H_
#define	_NGAP_FromEUTRANtoNGRAN_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_IntersystemSONeNBID.h"
#include "NGAP_IntersystemSONNGRANnodeID.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_FromEUTRANtoNGRAN */
typedef struct NGAP_FromEUTRANtoNGRAN {
	NGAP_IntersystemSONeNBID_t	 sourceeNBID;
	NGAP_IntersystemSONNGRANnodeID_t	 targetNGRANnodeID;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_FromEUTRANtoNGRAN_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_FromEUTRANtoNGRAN;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_FromEUTRANtoNGRAN_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_FromEUTRANtoNGRAN_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_FromEUTRANtoNGRAN_H_ */
#include <asn_internal.h>
