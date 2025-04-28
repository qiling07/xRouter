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
#include <stdbool.h>
#include <assert.h>


#define MIN_PORT 49152
#define MAX_PORT 65535
#define AVAILABLE_PORTS (MAX_PORT - MIN_PORT + 1)

#define TCP_CLOSED_TTL 10                // 10 seconds
#define TCP_INACTIVE_TTL 30                 // 10 minutes
#define NAT_INACTIVE_TTL 10                     // 2 minutes
#define NAT_TABLE_SIZE 1024

/* ---------------- NAT table ---------------- */
struct nat_entry {
    uint32_t int_ip;      // internal host IP
    uint32_t dst_ip;      // target IP

    uint16_t int_port;    // internal TCP/UDP port or ICMP identifier
    uint16_t dst_port;    // target TCP/UDP port or ICMP identifier

    uint8_t proto;        // IPPROTO_TCP / UDP / ICMP

    uint32_t ext_ip;      // external iface IP (SNAT)
    uint16_t ext_port;    // translated port / identifier

    time_t ts;            // last activity
    int is_static;        // flag to indicate static port forwarding entry (no timeout)
    uint8_t tcp_status;

    // Pointers for hash table chaining
    struct nat_entry *int_next;
    struct nat_entry *ext_next;
    
};

extern size_t entry_count;
extern struct nat_entry *nat_internal[NAT_TABLE_SIZE];
extern struct nat_entry *nat_external[NAT_TABLE_SIZE];


// struct nat_entry *nat_lookup(uint32_t ip, uint16_t port, uint8_t proto, int reverse);
// struct nat_entry *nat_create(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint8_t proto);
// void nat_lookup_and_remove(uint32_t ip, uint16_t port, uint8_t proto, int reverse);

struct nat_binding {
    bool is_valid;
    uint32_t int_ip;
    uint16_t int_port;
    uint32_t ext_ip;
    uint16_t ext_port;
    uint8_t proto;
};

struct nat_binding nat_lookup_outbound(uint32_t src_ip, uint16_t src_port, 
                                    uint32_t dst_ip, uint16_t dst_port, uint8_t proto,
                                    bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst);
struct nat_binding nat_lookup_inbound(uint32_t src_ip, uint16_t src_port, 
                                    uint32_t dst_ip, uint16_t dst_port, uint8_t proto,
                                    bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst);
struct nat_binding nat_lookup_or_create_outbound(uint32_t src_ip, uint16_t src_port, 
                                        uint32_t dst_ip, uint16_t dst_port, uint8_t proto, uint32_t ext_if_ip,
                                        bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst);

void nat_gc();
void nat_reset();

// port forwarding
struct nat_binding nat_add_port_forward(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint16_t ext_port, uint8_t proto);
int nat_delete_port_forward(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint16_t ext_port, uint8_t proto);

// printing
void print_nat_table(int static_only);
void get_nat_table_string(char *buf, size_t bufsize, int static_only);
void print_nat_entry(struct nat_entry *e, int static_only);

#endif