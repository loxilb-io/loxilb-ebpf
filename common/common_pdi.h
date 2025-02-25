/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __COMMON_PDI_H__
#define __COMMON_PDI_H__

#define none(x)  (x)

#define PDI_TYPEDEF(sz) pdi_tup##sz##_t
#define PDI_TYPEDEF_R(sz) pdi_tupr##sz##_t
#define PDI_TYPEDEF_ARR(sz,l) pdi_tuparr##sz##l##_t

#define PDI_DEF_FIELD(sz)       \
typedef struct pdi_tup##sz##_ { \
    __u##sz val;                \
    __u##sz valid;              \
} PDI_TYPEDEF(sz)

#define PDI_DEF_RANGE_FIELD(sz)   \
typedef struct pdi_tupwr##sz##_ { \
    uint32_t has_range;           \
    union {                     \
      struct pdi_tup##sz##r_  { \
      __u##sz min;              \
      __u##sz max;              \
      }r;                       \
      struct pdi_tup##sz##v_ {  \
        __u##sz val;            \
        __u##sz valid;          \
      }v;                       \
    }u;                         \
}pdi_tupr##sz##_t;

#define PDI_DEF_ARR_FIELD(sz,l)    \
typedef struct pdi_tuparr##sz##_ { \
    __u##sz val[l];                \
    __u##sz valid[l];              \
} PDI_TYPEDEF_ARR(sz, l)

PDI_DEF_FIELD(64);
PDI_DEF_FIELD(32);
PDI_DEF_RANGE_FIELD(16);
PDI_DEF_FIELD(16);
PDI_DEF_FIELD(8);
PDI_DEF_ARR_FIELD(8, 16);

#define PDI_DEF_ADDR6_FIELD PDI_TYPEDEF_ARR(8, 16)

#define PDI_MATCH(v1, v2) \
(((v2)->valid == 0) || ((v2)->valid && (((v1)->val & (v2)->valid) == (v2)->val)))

#define PDI_RMATCH(v1, v2) \
(((v2)->has_range && ((v1)->u.v.val >= (v2)->u.r.min && (v1)->u.v.val <= (v2)->u.r.max)) || \
 (((v2)->has_range == 0 ) && (((v2)->u.v.valid == 0) || ((v2)->u.v.valid && (((v1)->u.v.val & (v2)->u.v.valid) == (v2)->u.v.val)))))

#define PDI_MATCH_ALL(v1, v2) \
(((v2)->valid == (v1)->valid) && (((v1)->val & (v2)->valid) == (v2)->val))

#define PDI_RMATCH_ALL(v1, v2) \
((((v2)->has_range == (v1)->has_range) && ((v1)->u.v.val >= (v2)->u.r.min && (v1)->u.v.val <= (v2)->u.r.max)) || \
 (((v2)->has_range != 0) &&(((v2)->u.v.valid == (v1)->u.v.valid) && (((v1)->u.v.val & (v2)->u.v.valid) == (v2)->u.v.val))))

#define PDI_MATCH6(v1, v2) ({ \
    int match = 1; \
    for (int i = 0; i < 16; i++) { \
        if ((v2)->valid[i] != 0 && ((v1)->val[i] & (v2)->valid[i]) != (v2)->val[i]) { \
            match = 0; \
            break; \
        } \
    } \
    match; \
})

#define PDI_MATCH6_ALL(v1, v2) ({ \
    int match = 1; \
    for (int i = 0; i < 16; i++) { \
        if ((v2)->valid[i] != (v1)->valid[i] && ((v1)->val[i] & (v2)->valid[i]) != (v2)->val[i]) { \
            match = 0; \
            break; \
        } \
    } \
    match; \
})

#define PDI_MATCH_INIT(v1, v, vld)           \
do {                                         \
  (v1)->valid = vld;                         \
  (v1)->val = (v) & (v1)->valid;             \
} while (0)

#define PDI_MATCH6_INIT(v1, v, vld)          \
do {                                         \
  for (int i = 0; i < 16; i++) {             \
    (v1)->valid[i] = ((uint8_t *)(vld))[i];  \
    (v1)->val[i] = ((uint8_t *)(v))[i] & (v1)->valid[i];   \
  }                                          \
} while (0)

#define PDI_RMATCH_INIT(v1, hr, val1, val2)  \
do {                                         \
  if (hr) {                                  \
    (v1)->u.r.min = val1;                    \
    (v1)->u.r.max = val2;                    \
    (v1)->has_range = 1;                     \
  } else {                                   \
    (v1)->u.v.valid = val2;                  \
    (v1)->u.v.val = val1 & (v1)->u.v.valid;  \
    (v1)->has_range = 0;                     \
  }                                          \
} while (0)

#define PDI_MATCH_COPY(v1, v2)               \
do {                                         \
  (v1)->valid = (v2)->valid;                 \
  (v1)->val = (v2)->val;                     \
} while (0)

#define PDI_RMATCH_COPY(v1, v2)              \
do {                                         \
  if ((v2)->has_range) {                     \
    (v1)->has_range = (v2)->has_range;       \
    (v1)->u.r.min = (v2)->u.r.min;           \
    (v1)->u.r.max = (v2)->u.r.max;           \
  } else {                                   \
    (v1)->has_range = 0;                     \
    (v1)->u.v.valid = (v2)->u.v.valid;       \
    (v1)->u.v.val = (v2)->u.v.val;           \
  }                                          \
} while (0)

#define PDI_MATCH6_COPY(v1, v2)              \
do {                                         \
  memcpy((v1)->valid, (v2)->valid, sizeof((v1)->valid)); \
  memcpy((v1)->val, (v2)->val, sizeof((v1)->val)); \
} while (0)

#define PDI_VAL_INIT(v1, v)                  \
do {                                         \
  (v1)->valid = -1;                          \
  (v1)->val = (v);                           \
} while (0)

#define PDI_RVAL_INIT(v1, val1)              \
do {                                         \
    (v1)->u.v.valid = -1;                    \
    (v1)->u.v.val = val1;                    \
    (v1)->has_range = 0;                     \
} while (0)

#define PDI_VAL6_INIT(v1, v)                 \
do {                                         \
  memset((v1)->valid, 0xff, sizeof((v1)->valid)); \
  memcpy((v1)->val, v, sizeof((v1)->val));   \
} while (0)

struct pdi_key {
  PDI_TYPEDEF(32)    dest;
  PDI_TYPEDEF(32)    source;
  PDI_TYPEDEF_R(16)  dport;
  PDI_TYPEDEF_R(16)  sport;
  PDI_TYPEDEF(16)    inport;
  PDI_TYPEDEF(16)    zone;
  PDI_TYPEDEF(16)    bd;
  PDI_TYPEDEF(8)     protocol;
  PDI_TYPEDEF(8)     nr;
};

struct pdi6_key {
  PDI_DEF_ADDR6_FIELD dest;
  PDI_DEF_ADDR6_FIELD source;
  PDI_TYPEDEF_R(16)  dport;
  PDI_TYPEDEF_R(16)  sport;
  PDI_TYPEDEF(16)    inport;
  PDI_TYPEDEF(16)    zone;
  PDI_TYPEDEF(16)    bd;
  PDI_TYPEDEF(8)     protocol;
  PDI_TYPEDEF(8)     nr;
};

#endif
