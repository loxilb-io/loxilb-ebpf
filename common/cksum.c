#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

static unsigned short
calc_csum(unsigned short *addr, unsigned int count)
{
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }

  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }

  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void
calc_ip_csum(struct ip_header *iph)
{
  iph->ip_csum = 0;
  iph->ip_csum = calc_csum((unsigned short*)iph,
                            IP_IHL(iph->ip_ihl_ver) <<2);
}

