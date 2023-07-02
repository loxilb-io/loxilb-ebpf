/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <stdio.h>
#include "loxilb_libdp.h"

extern int loxilb_main(struct ebpfcfg *cfg);
extern int llb_packet_trace_en(int en);
extern int llb_setup_pkt_ring(void);

static void
print_usage(void)
{
  printf("**** loxilb debugger usage  ****\n");
  printf("./pgm trace all\n");
  printf("./pgm trace excp\n");
  printf("./pgm trace disable\n");
  printf("\n\nPress CTRL-C to exit program\n");
  printf("********************************\n");
}

int main(int argc, char *argv[])
{
  struct ebpfcfg cfg;
  int pten = 0;

  if (argc != 3) {
    print_usage();
    exit(1);
  }

  for (int i = 1; i < argc; i++) {
    switch (i) {
    case 1:
      if (strcmp(argv[i], "trace") != 0) {
        print_usage();
        exit(1);
      }
      break;
    case 2:
      if (strcmp(argv[i], "all") == 0) {
        pten = 2;
      } else if (strcmp(argv[i], "excp") == 0) {
        pten = 1;
      } else if (strcmp(argv[i], "disable") == 0) {
        pten = 0;
      } else {
        print_usage();
        exit(1);
      }
      break;
    default:
      print_usage();
      exit(1);
    }
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.no_loader = 1;
  cfg.have_ptrace = 1;
  loxilb_main(&cfg);

  llb_packet_trace_en(pten);

  if (pten) {
    llb_setup_pkt_ring();
    while (1) {
      sleep(1);
    }
  }
}
