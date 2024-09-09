include Makefile.am.libasncodec

NAME=llbngap
LIBNAME=lib-$(NAME)
PREFIX?=/usr/local/sbin/

LIBS += -lm
CFLAGS += $(ASN_MODULE_CFLAGS) -DASN_PDU_COLLECTION -I.
ASN_LIBRARY ?= $(LIBNAME).a

.PHONY: install uninstall

all: $(ASN_LIBRARY)

$(ASN_LIBRARY): $(ASN_MODULE_SRCS:.c=.o)
	$(AR) rcs $@ $(ASN_MODULE_SRCS:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(ASN_MODULE_SRCS:.c=.o) $(ASN_LIBRARY)
