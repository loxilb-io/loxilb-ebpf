/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_HandoverRequiredTransfer_H_
#define	_NGAP_HandoverRequiredTransfer_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_DirectForwardingPathAvailability.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_HandoverRequiredTransfer */
typedef struct NGAP_HandoverRequiredTransfer {
	NGAP_DirectForwardingPathAvailability_t	*directForwardingPathAvailability;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_HandoverRequiredTransfer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_HandoverRequiredTransfer;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_HandoverRequiredTransfer_H_ */
#include <asn_internal.h>
