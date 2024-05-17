# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_DEPS := llb_kern_devif.c      \
            llb_kern_l2fwd.c      \
            llb_kern_l3fwd.c      \
            llb_kern_sessfwd.c    \
            llb_kern_natlbfwd.c   \
            llb_kern_policer.c    \
            llb_kern_fcfwd.c      \
            llb_kern_entry.c      \
            llb_kern_ct.c

XDP_TARGETS  := llb_xdp_main
TC_TARGETS   := llb_ebpf_main
TC_ETARGETS  := llb_ebpf_emain
MON_TARGETS  := llb_kern_mon
USER_TARGETS := loxilb_libdp

SOCK_TARGETS       := llb_kern_sock
SOCKMAP_TARGETS    := llb_kern_sockmap
SOCKSTREAM_TARGETS := llb_kern_sockstream
SOCKDIR_TARGETS    := llb_kern_sockdirect

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

LDFLAGS +=  -lz 

include $(COMMON_DIR)/common.mk
