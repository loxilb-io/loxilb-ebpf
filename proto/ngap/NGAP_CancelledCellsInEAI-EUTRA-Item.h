/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_CancelledCellsInEAI_EUTRA_Item_H_
#define	_NGAP_CancelledCellsInEAI_EUTRA_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_EUTRA-CGI.h"
#include "NGAP_NumberOfBroadcasts.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_CancelledCellsInEAI-EUTRA-Item */
typedef struct NGAP_CancelledCellsInEAI_EUTRA_Item {
	NGAP_EUTRA_CGI_t	 eUTRA_CGI;
	NGAP_NumberOfBroadcasts_t	 numberOfBroadcasts;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_CancelledCellsInEAI_EUTRA_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_CancelledCellsInEAI_EUTRA_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_CancelledCellsInEAI_EUTRA_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_CancelledCellsInEAI_EUTRA_Item_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_CancelledCellsInEAI_EUTRA_Item_H_ */
#include <asn_internal.h>
