/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_Cell_CAGInformation_H_
#define	_NGAP_Cell_CAGInformation_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_NGRAN-CGI.h"
#include "NGAP_CellCAGList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_Cell-CAGInformation */
typedef struct NGAP_Cell_CAGInformation {
	NGAP_NGRAN_CGI_t	 nGRAN_CGI;
	NGAP_CellCAGList_t	 cellCAGList;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_Cell_CAGInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_Cell_CAGInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_Cell_CAGInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_Cell_CAGInformation_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_Cell_CAGInformation_H_ */
#include <asn_internal.h>
