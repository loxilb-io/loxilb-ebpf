/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <stdio.h>
#include "loxilb_libdp.h"

extern int loxilb_main(struct ebpfcfg *cfg);
extern int llb_packet_trace_en(int en);
extern int llb_setup_pkt_ring(void);

/* ct_fail_stats_map indices, see enum llb_ct_fail */
static const char *ct_fail_names[LLB_CT_FAIL_MAX] = {
  "map-full", "half-insert", "xkey-exist", "xkey-miss"
};

static void
print_usage(void)
{
  printf("**** loxilb debugger usage  ****\n");
  printf("./pgm trace all\n");
  printf("./pgm trace excp\n");
  printf("./pgm trace disable\n");
  printf("./pgm stats ctfail     (conntrack insert/lookup failures)\n");
  printf("\n\nPress CTRL-C to exit program\n");
  printf("********************************\n");
}

static void
print_ct_fail_stats(void)
{
  int i;

  printf("%-12s %12s %12s\n", "reason", "packets", "bytes");
  for (i = 0; i < LLB_CT_FAIL_MAX; i++) {
    uint64_t bytes = 0;
    uint64_t pkts = 0;

    if (llb_fetch_map_stats_cached(LL_DP_CT_FAIL_STATS_MAP, i, 1,
                                   &bytes, &pkts) != 0) {
      printf("%-12s %12s\n", ct_fail_names[i], "n/a");
      continue;
    }
    printf("%-12s %12llu %12llu\n", ct_fail_names[i],
           (unsigned long long)pkts, (unsigned long long)bytes);
  }
}

int main(int argc, char *argv[])
{
  struct ebpfcfg cfg;
  int pten = 0;
  int ctfail = 0;

  if (argc != 3) {
    print_usage();
    exit(1);
  }

  for (int i = 1; i < argc; i++) {
    switch (i) {
    case 1:
      if (strcmp(argv[i], "stats") == 0) {
        ctfail = 1;
      } else if (strcmp(argv[i], "trace") != 0) {
        print_usage();
        exit(1);
      }
      break;
    case 2:
      if (ctfail) {
        if (strcmp(argv[i], "ctfail") != 0) {
          print_usage();
          exit(1);
        }
      } else if (strcmp(argv[i], "all") == 0) {
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
  cfg.have_ptrace = ctfail ? 0 : 1;
  /* stats output should not be interleaved with libdp's map-open traces */
  cfg.loglevel = ctfail ? LOG_WARN : 0;
  loxilb_main(&cfg);

  if (ctfail) {
    print_ct_fail_stats();
    return 0;
  }

  llb_packet_trace_en(pten);

  if (pten) {
    llb_setup_pkt_ring();
    while (1) {
      sleep(1);
    }
  }
}
