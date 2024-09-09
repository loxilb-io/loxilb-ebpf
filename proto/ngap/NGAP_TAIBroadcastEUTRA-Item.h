/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_TAIBroadcastEUTRA_Item_H_
#define	_NGAP_TAIBroadcastEUTRA_Item_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_TAI.h"
#include "NGAP_CompletedCellsInTAI-EUTRA.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_ProtocolExtensionContainer;

/* NGAP_TAIBroadcastEUTRA-Item */
typedef struct NGAP_TAIBroadcastEUTRA_Item {
	NGAP_TAI_t	 tAI;
	NGAP_CompletedCellsInTAI_EUTRA_t	 completedCellsInTAI_EUTRA;
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_TAIBroadcastEUTRA_Item_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_TAIBroadcastEUTRA_Item;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_TAIBroadcastEUTRA_Item_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_TAIBroadcastEUTRA_Item_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_TAIBroadcastEUTRA_Item_H_ */
#include <asn_internal.h>
