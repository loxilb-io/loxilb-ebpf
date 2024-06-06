/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_ReportingPeriodicity_H_
#define	_NGAP_ReportingPeriodicity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_ReportingPeriodicity {
	NGAP_ReportingPeriodicity_stop	= 0,
	NGAP_ReportingPeriodicity_single	= 1,
	NGAP_ReportingPeriodicity_ms1000	= 2,
	NGAP_ReportingPeriodicity_ms2000	= 3,
	NGAP_ReportingPeriodicity_ms5000	= 4,
	NGAP_ReportingPeriodicity_ms10000	= 5
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_ReportingPeriodicity;

/* NGAP_ReportingPeriodicity */
typedef long	 NGAP_ReportingPeriodicity_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_ReportingPeriodicity_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_ReportingPeriodicity;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_ReportingPeriodicity_specs_1;
asn_struct_free_f NGAP_ReportingPeriodicity_free;
asn_struct_print_f NGAP_ReportingPeriodicity_print;
asn_constr_check_f NGAP_ReportingPeriodicity_constraint;
per_type_decoder_f NGAP_ReportingPeriodicity_decode_aper;
per_type_encoder_f NGAP_ReportingPeriodicity_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_ReportingPeriodicity_H_ */
#include <asn_internal.h>