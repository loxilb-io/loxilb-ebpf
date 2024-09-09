/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_OnboardingSupport_H_
#define	_NGAP_OnboardingSupport_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_OnboardingSupport {
	NGAP_OnboardingSupport_true	= 0
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_OnboardingSupport;

/* NGAP_OnboardingSupport */
typedef long	 NGAP_OnboardingSupport_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_OnboardingSupport_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_OnboardingSupport;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_OnboardingSupport_specs_1;
asn_struct_free_f NGAP_OnboardingSupport_free;
asn_struct_print_f NGAP_OnboardingSupport_print;
asn_constr_check_f NGAP_OnboardingSupport_constraint;
per_type_decoder_f NGAP_OnboardingSupport_decode_aper;
per_type_encoder_f NGAP_OnboardingSupport_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_OnboardingSupport_H_ */
#include <asn_internal.h>
