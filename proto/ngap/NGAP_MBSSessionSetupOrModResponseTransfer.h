/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_MBSSessionSetupOrModResponseTransfer_H_
#define	_NGAP_MBSSessionSetupOrModResponseTransfer_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct NGAP_MBS_SessionTNLInfoNGRAN;
struct NGAP_ProtocolExtensionContainer;

/* NGAP_MBSSessionSetupOrModResponseTransfer */
typedef struct NGAP_MBSSessionSetupOrModResponseTransfer {
	struct NGAP_MBS_SessionTNLInfoNGRAN	*mBS_SessionTNLInfoNGRAN;	/* OPTIONAL */
	struct NGAP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_MBSSessionSetupOrModResponseTransfer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_MBSSessionSetupOrModResponseTransfer;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_MBSSessionSetupOrModResponseTransfer_H_ */
#include <asn_internal.h>
