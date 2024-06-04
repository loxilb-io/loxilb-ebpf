# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_user_bpf_xdp.o common_libbpf.o common_pdi.o common_sum.o common_frame.o log.o throttler.o cgroup.o sockproxy.o notify.o ngap_helper.o

CFLAGS := -g -Wall -I../libbpf/src/

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/  -I../headers -I../proto/ngap/

common_user_bpf_xdp.o: common_user_bpf_xdp.c common_user_bpf_xdp.h common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_libbpf.o: common_libbpf.c common_libbpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_check.o: common_sum.c common_sum.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_frame.o: common_frame.c common_frame.h
	$(CC) $(CFLAGS) -c -o $@ $<

cgroup.o: cgroup.c cgroup.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy.o: sockproxy.c sockproxy.h
	$(CC) $(CFLAGS) -c -o $@ $<

notify.o: notify.c notify.h
	$(CC) $(CFLAGS) -c -o $@ $<

ngap_helper.o: ngap_helper.c ngap_helper.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
