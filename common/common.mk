# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC = llc
CLANG := $(shell if [ -f /usr/bin/clang-10 ];then echo clang-10; else echo clang; fi;)
CC ?= gcc
BPFTOOL ?= bpftool

XDP_C = ${XDP_TARGETS:=.c}
TC_C = ${TC_TARGETS:=.c}
TC_EC = ${TC_ETARGETS:=.c}
MON_C = ${MON_TARGETS:=.c}
SOCK_C = ${SOCK_TARGETS:=.c}
SM_C = ${SOCKMAP_TARGETS:=.c}
STREAM_C = ${SOCKSTREAM_TARGETS:=.c}
SOCKDIR_C = ${SOCKDIR_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
TC_OBJ = ${TC_C:.c=.o}
TC_EOBJ = ${TC_EC:.c=.o}
MON_OBJ = ${MON_C:.c=.o}
SOCK_OBJ = ${SOCK_C:.c=.o}
SM_OBJ = ${SM_C:.c=.o}
STREAM_OBJ = ${STREAM_C:.c=.o}
SOCKDIR_OBJ = ${SOCKDIR_C:.c=.o}

USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}
USER_TARGETS_LIB := libloxilbdp.a

UNAME := $(shell uname -m)
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
ifeq ($(UNAME), aarch64)
ARCH=arm64
endif

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
  | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
  Q =
  msg =
else
  Q = @
  msg = @printf '  %-8s %s%s\n'         \
          "$(1)"            \
          "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
          "$(if $(3), $(3))";
  MAKEFLAGS += --no-print-directory
endif


# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/
LIBBPF_DIR ?= ../libbpf/src/

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_sum.o $(COMMON_DIR)/common_libbpf.o $(COMMON_DIR)/common_pdi.o $(COMMON_DIR)/common_frame.o $(COMMON_DIR)/log.o $(COMMON_DIR)/throttler.o $(COMMON_DIR)/cgroup.o $(COMMON_DIR)/sockproxy.o $(COMMON_DIR)/notify.o $(COMMON_DIR)/picohttpparser.o $(COMMON_DIR)/llhttp.o $(COMMON_DIR)/httpapi.o $(COMMON_DIR)/http.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

CFLAGS_ALL ?= -DHAVE_DP_FC=1 -DHAVE_DP_EXTCT=1 -DHAVE_DP_SCTP_SUM=1 -DHAVE_DP_CT_SYNC=1 -DMAX_REAL_CPUS=16 -DHAVE_DP_RSS=1 -DHAVE_DP_PERSIST_TFC=1
ifeq ($(CLANG), clang-13)
CFLAGS_ALL += -DHAVE_CLANG13
endif
CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -g
CFLAGS += -I../headers/ -I$(LIBBPF_DIR)/ $(CFLAGS_ALL)
LDFLAGS ?= -L$(LIBBPF_DIR)

ifeq ($(DOCKER_BUILDX_ARM64), true)
CFLAGS_ALL += -DDOCKER_BUILDX_ARM64=1
endif

BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/ -I/usr/include/$(shell uname -m)-linux-gnu $(CFLAGS_ALL)

LIBS = $(OBJECT_LIBBPF) -lelf $(USER_LIBS) -lz -lpthread -lssl -lcrypto

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(TC_OBJ) $(TC_EOBJ) $(MON_OBJ) $(SOCK_OBJ) $(SM_OBJ) $(STREAM_OBJ) $(SOCKDIR_OBJ) $(USER_TARGETS_LIB)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(TC_OBJ) $(TC_EOBJ) $(MON_OBJ) $(MON_OBJ) $(SOCK_OBJ) $(SM_OBJ) $(STREAM_OBJ) $(SOCKDIR_OBJ) $(USER_TARGETS_LIB)
	rm -f loxilb_dp_debug 
	rm -f vmlinux vmlinux.h
	rm -f *skel*.h
	rm -f $@
	rm -f *.ll
	rm -f *~

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(OBJECT_LIBBPF):
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
		DESTDIR=build $(MAKE) install; \
	fi

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS) %.skel.h
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o loxilb_dp_debug loxilb_dp_debug.c $(COMMON_OBJS) $< $(LIBS)
	@touch $@

$(USER_TARGETS_LIB): %: $(USER_OBJ) $(COMMON_OBJS)
	$(AR) rcu $@ $^
	ranlib $@

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/

## Remove debug in production
## -DLL_XDP_DEBUG=1

$(TC_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(TC_EOBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-DLL_TC_EBPF=1 \
		-DLL_TC_EBPF_EHOOK=1 \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo mkdir -p /opt/loxilb/
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

vmlinux.h:
	@touch $@

vmlinux: vmlinux.h
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@touch $@

$(MON_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) $(XDP_DEPS) vmlinux
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(SOCK_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) 
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		-DLL_TC_EBPF=1 \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@#$(LLC) -march=bpf -mattr=dwarfris -filetype=obj -o $@ ${@:.o=.o}
	@sudo cp $@ /opt/loxilb/
	@#sudo pahole -J /opt/loxilb/$@

$(SM_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) vmlinux
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

$(STREAM_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

$(SOCKDIR_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-D __BPF_TRACING__ \
		-D__TARGET_ARCH_$(ARCH) \
		$(BPF_CFLAGS) \
		$(CLANG_BPF_SYS_INCLUDES) \
		-O2 -g -c -o ${@:.o=.o} $<
	@sudo cp $@ /opt/loxilb/

# Generate BPF skeletons
%.skel.h: $(MON_OBJ)
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

install:
	@sudo cp -f /opt/loxilb/llb_*.o ${dpinstalldir}/
	@sudo cp -fr ../libbpf/src/build/* ${dpinstalldir}/
