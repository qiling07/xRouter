#ifndef __TABLE_H
#define __TABLE_H

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#define NAT_TTL 120 // seconds
#define NAT_TABLE_SIZE 1024

/* ---------------- NAT table ---------------- */
struct nat_entry {
    uint32_t int_ip;      // internal host IP
    uint16_t int_port;    // TCP/UDP port or ICMP identifier
    uint32_t ext_ip;      // external iface IP (SNAT)
    uint16_t ext_port;    // translated port / identifier
    uint8_t proto;        // IPPROTO_TCP / UDP / ICMP
    time_t ts;            // last activity
    uint8_t ext_fin = 0;
    uint8_t int_fin = 0;
    uint8_t last_ack = 0;
    // Pointers for hash table chaining
    struct nat_entry *int_next;
    struct nat_entry *ext_next;
    int is_static; // flag to indicate static port forwarding entry (no timeout)
};

extern struct nat_entry *nat_internal[NAT_TABLE_SIZE];
extern struct nat_entry *nat_external[NAT_TABLE_SIZE];

extern size_t entry_count;

struct nat_entry *nat_lookup(uint32_t ip, uint16_t port, uint8_t proto, int reverse);
int is_ext_port_taken(uint16_t ext_port, uint8_t proto);
struct nat_entry *nat_create(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint8_t proto);
struct nat_entry *nat_add_port_forward(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint16_t ext_port, uint8_t proto);
void nat_lookup_and_remove(uint32_t ip, uint16_t port, uint8_t proto, int reverse);
void nat_gc();
void nat_reset();

void print_nat_table();
void get_nat_table_string(char *buf, size_t bufsize);

#endif