/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_M6Configuration_H_
#define	_NGAP_M6Configuration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_M6report-Interval.h"
#include "NGAP_Links-to-log.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_M6Configuration */
typedef struct NGAP_M6Configuration {
	NGAP_M6report_Interval_t	 m6report_Interval;
	NGAP_Links_to_log_t	 m6_links_to_log;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_M6Configuration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_M6Configuration;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_M6Configuration_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_M6Configuration_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_M6Configuration_H_ */
#include <asn_internal.h>