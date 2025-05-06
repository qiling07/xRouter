#ifndef __DEBUG_PRINT_H
#define __DEBUG_PRINT_H

#include <stdint.h>
#include <stdlib.h>

void print_payload(const unsigned char *payload, int len);
void dump_payload(const unsigned char *d, int len);
const char *proto_name(uint8_t p);
void print_tcpdump_packet(void *ip_pkt, const char *iface);
void dump_eth_ip_udp(const uint8_t *buf, size_t len);




#endif