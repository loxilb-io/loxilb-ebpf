/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_MaximumIntegrityProtectedDataRate_H_
#define	_NGAP_MaximumIntegrityProtectedDataRate_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_MaximumIntegrityProtectedDataRate {
	NGAP_MaximumIntegrityProtectedDataRate_bitrate64kbs	= 0,
	NGAP_MaximumIntegrityProtectedDataRate_maximum_UE_rate	= 1
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_MaximumIntegrityProtectedDataRate;

/* NGAP_MaximumIntegrityProtectedDataRate */
typedef long	 NGAP_MaximumIntegrityProtectedDataRate_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_MaximumIntegrityProtectedDataRate_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_MaximumIntegrityProtectedDataRate;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_MaximumIntegrityProtectedDataRate_specs_1;
asn_struct_free_f NGAP_MaximumIntegrityProtectedDataRate_free;
asn_struct_print_f NGAP_MaximumIntegrityProtectedDataRate_print;
asn_constr_check_f NGAP_MaximumIntegrityProtectedDataRate_constraint;
per_type_decoder_f NGAP_MaximumIntegrityProtectedDataRate_decode_aper;
per_type_encoder_f NGAP_MaximumIntegrityProtectedDataRate_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_MaximumIntegrityProtectedDataRate_H_ */
#include <asn_internal.h>
