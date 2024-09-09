/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "./ngap.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER -no-gen-JER`
 */

#ifndef	_NGAP_ReportIntervalMDT_H_
#define	_NGAP_ReportIntervalMDT_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_ReportIntervalMDT {
	NGAP_ReportIntervalMDT_ms120	= 0,
	NGAP_ReportIntervalMDT_ms240	= 1,
	NGAP_ReportIntervalMDT_ms480	= 2,
	NGAP_ReportIntervalMDT_ms640	= 3,
	NGAP_ReportIntervalMDT_ms1024	= 4,
	NGAP_ReportIntervalMDT_ms2048	= 5,
	NGAP_ReportIntervalMDT_ms5120	= 6,
	NGAP_ReportIntervalMDT_ms10240	= 7,
	NGAP_ReportIntervalMDT_min1	= 8,
	NGAP_ReportIntervalMDT_min6	= 9,
	NGAP_ReportIntervalMDT_min12	= 10,
	NGAP_ReportIntervalMDT_min30	= 11,
	NGAP_ReportIntervalMDT_min60	= 12
} e_NGAP_ReportIntervalMDT;

/* NGAP_ReportIntervalMDT */
typedef long	 NGAP_ReportIntervalMDT_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_ReportIntervalMDT_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_ReportIntervalMDT;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_ReportIntervalMDT_specs_1;
asn_struct_free_f NGAP_ReportIntervalMDT_free;
asn_struct_print_f NGAP_ReportIntervalMDT_print;
asn_constr_check_f NGAP_ReportIntervalMDT_constraint;
per_type_decoder_f NGAP_ReportIntervalMDT_decode_aper;
per_type_encoder_f NGAP_ReportIntervalMDT_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_ReportIntervalMDT_H_ */
#include <asn_internal.h>
