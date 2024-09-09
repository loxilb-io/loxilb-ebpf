# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_libbpf.o common_pdi.o common_sum.o common_frame.o log.o throttler.o cgroup.o sockproxy.o notify.o picohttpparser.o llhttp.o httpapi.o http.o ngap_helper.o

CFLAGS := -g -Wall -I../libbpf/src/

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/  -I../headers -I../proto/ngap/

common_libbpf.o: common_libbpf.c common_libbpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_pdi.o: common_pdi.c common_pdi.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_sum.o: common_sum.c common_sum.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_frame.o: common_frame.c common_frame.h
	$(CC) $(CFLAGS) -c -o $@ $<

log.o: log.c log.h
	$(CC) $(CFLAGS) -c -o $@ $<

throttler.o: throttler.c throttler.h
	$(CC) $(CFLAGS) -c -o $@ $<

cgroup.o: cgroup.c cgroup.h
	$(CC) $(CFLAGS) -c -o $@ $<

sockproxy.o: sockproxy.c sockproxy.h
	$(CC) $(CFLAGS) -c -o $@ $<

notify.o: notify.c notify.h
	$(CC) $(CFLAGS) -c -o $@ $<

picohttpparser.o: picohttpparser.c picohttpparser.h
	$(CC) $(CFLAGS) -c -o $@ $<

llhttp.o: llhttp.c llhttp.h
	$(CC) $(CFLAGS) -c -o $@ $<

httpapi.o: httpapi.c
	$(CC) $(CFLAGS) -c -o $@ $<

http.o: http.c
	$(CC) $(CFLAGS) -c -o $@ $<

llhttp.a: llhttp.o llhttpapi.o http.o
	$(AR) rcs -c $@ $^

ngap_helper.o: ngap_helper.c ngap_helper.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
