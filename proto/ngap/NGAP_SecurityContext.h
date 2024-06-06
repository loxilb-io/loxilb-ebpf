/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_SecurityContext_H_
#define	_NGAP_SecurityContext_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_NextHopChainingCount.h"
#include "NGAP_SecurityKey.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_SecurityContext */
typedef struct NGAP_SecurityContext {
	NGAP_NextHopChainingCount_t	 nextHopChainingCount;
	NGAP_SecurityKey_t	 nextHopNH;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_SecurityContext_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_SecurityContext;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_SecurityContext_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_SecurityContext_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_SecurityContext_H_ */
#include <asn_internal.h>