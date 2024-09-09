/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_RIMInformation_H_
#define	_NGAP_RIMInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_GNBSetID.h"
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_RIMInformation__rIM_RSDetection {
	NGAP_RIMInformation__rIM_RSDetection_rs_detected	= 0,
	NGAP_RIMInformation__rIM_RSDetection_rs_disappeared	= 1
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_RIMInformation__rIM_RSDetection;

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_RIMInformation */
typedef struct NGAP_RIMInformation {
	NGAP_GNBSetID_t	 targetgNBSetID;
	long	 rIM_RSDetection;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_RIMInformation_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_NGAP_rIM_RSDetection_3;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_RIMInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_RIMInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_RIMInformation_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_RIMInformation_H_ */
#include <asn_internal.h>
