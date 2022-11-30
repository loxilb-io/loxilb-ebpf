#ifndef __COMMON_CHECKSUM_H__
#define __COMMON_CHECKSUM_H__

void calc_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);
void calc_ip_csum(struct iphdr *iph);

#endif
