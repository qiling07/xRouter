// nat_sniffer.c – User‑space NAT with TCP/UDP/ICMP support & payload dump
// -------------------------------------------------------------------------
// Build : gcc -Wall -O2 nat_sniffer.c -o nat_sniffer
// Run   : sudo ./nat_sniffer <int_if> <ext_if>
// -------------------------------------------------------------------------

#define _GNU_SOURCE
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

#include "table.h"
#include "debug_print.h"
#include "utils.h"

interface_info int_if_info, ext_if_info;
static int raw_int = -1, raw_ext = -1;

static void cleanup(int sig) {
    if (raw_int != -1)
        close(raw_int);
    if (raw_ext != -1)
        close(raw_ext);
    puts("\n[+] NAT stopped.");
    exit(0);
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <int_if> <ext_if>\n", argv[0]);
        return 1;
    }
    srand(time(NULL));
    const char *int_if = argv[1], *ext_if = argv[2];
    raw_int = create_raw(int_if);
    raw_ext = create_raw(ext_if);
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    unsigned char buf[BUF_SZ];
    puts("[+] User‑space NAT running… Ctrl‑C to quit.\n");
    
    if (get_interface_info(int_if, &int_if_info) == -1) {
        fprintf(stderr, "Failed to get info for interface %s\n", int_if);
        return 1;
    }
    if (get_interface_info(ext_if, &ext_if_info) == -1) {
        fprintf(stderr, "Failed to get info for interface %s\n", ext_if);
        return 1;
    }

    // get default gateway ip
    uint32_t gw_ip_le;
    uint8_t gw_mac[6];
    char gw_mac_str[40];

    if (get_default_gw(ext_if, sizeof(ext_if), &gw_ip_le) == -1) {
        fprintf(stderr, "No default gateway found\n");
        return 1;
    }

    // get default gateway mac
    struct in_addr gw_ip;
    gw_ip.s_addr = gw_ip_le;
    printf("Gateway IP = %s\n", inet_ntoa(gw_ip));

    if (get_mac_from_arp(gw_ip_le, gw_mac) == -1) {
        fprintf(stderr, "Gateway %s (%s) not in ARP cache\n",
                ext_if, inet_ntoa(gw_ip));
        return 1;
    }
    // just for debugging
    mac_bin2str(gw_mac, gw_mac_str, sizeof(gw_mac_str));
    printf("Gateway MAC = %s -------------------\n", gw_mac_str);

    while (1) {
        nat_gc();
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(raw_int, &rd);
        FD_SET(raw_ext, &rd);
        int maxfd = (raw_int > raw_ext ? raw_int : raw_ext);
        if (select(maxfd + 1, &rd, NULL, NULL, NULL) == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }

        /* -------- internal → external -------- */
        if (FD_ISSET(raw_int, &rd)) {
            /** filter out IP packets of interest :
             * IPv4 packets with correct checksum (TODO)
             * from a private source address on the LAN (TODO)
             * to a public destination address (TODO)
             * with a TCP/UDP/ICMP header (TODO)
            */
            ssize_t n = recv(raw_int, buf, BUF_SZ, 0);
            if (n <= 0) continue;

            struct ether_header *eth = (struct ether_header *) buf;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

            struct ip *ip = (uintptr_t)buf + sizeof(*eth);
            if (ip->ip_src.s_addr == int_if_info.ip_addr.s_addr) continue;
            if (checksum(ip, ip->ip_hl * 4) != 0) {
                fprintf(stderr, "Invalid IP checksum\n");
                continue;
            }
            if (is_host_address(ntohl(ip->ip_src.s_addr), &int_if_info) == 0) {
                fprintf(stderr, "Not a host address\n");
                continue;
            }
            if (is_public_address(ntohl(ip->ip_dst.s_addr)) == 0) {
                fprintf(stderr, "Not a public address\n");
                continue;
            }
            if (!(ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP || ip->ip_p == IPPROTO_ICMP)) {
                fprintf(stderr, "Not TCP/UDP/ICMP\n");
                continue;
            }


            // printf("INT");
            // printf("src=%s ", inet_ntoa(ip->ip_src));
            // printf("dst=%s proto=%s\n", inet_ntoa(ip->ip_dst), proto_name(ip->ip_p));
            // printf("length=%d", ip->ip_hl*4);

            /** extract out (ip, port/id) for NAT translation */
            void *l4 = (unsigned char *)ip + ip->ip_hl * 4;
            uint16_t id_or_port = 0;
            size_t hdr_add = 0;
            if (ip->ip_p == IPPROTO_TCP) {
                struct tcphdr *t = l4;
                id_or_port = ntohs(t->source);
                hdr_add = t->doff * 4;
                t->check = 0;
            } else if (ip->ip_p == IPPROTO_UDP) {
                struct udphdr *u = l4;
                id_or_port = ntohs(u->source);
                hdr_add = sizeof(struct udphdr);
                u->check = 0;
            } else if (ip->ip_p == IPPROTO_ICMP) {
                struct icmphdr *icmp = l4;
                id_or_port = ntohs(*(uint16_t *)(l4 + 4)); // identifier is at offset 4
                hdr_add = sizeof(struct icmphdr);
                icmp->checksum = 0;
            }

            struct nat_entry *e = nat_lookup(ip->ip_src.s_addr, id_or_port, ip->ip_p, 0);
            if (!e) {
                e = nat_create(ip->ip_src.s_addr, id_or_port, ext_if_info.ip_addr.s_addr, ip->ip_p);
            }
            // printf("nat table after insertion\n");
            // print_nat_table();
            e->ts = time(NULL);
            ip->ip_src.s_addr = e->ext_ip; // port/identifier translation only for TCP/UDP
            if (ip->ip_p == IPPROTO_TCP) {
                ((struct tcphdr *)l4)->source = htons(e->ext_port);
            } else if (ip->ip_p == IPPROTO_UDP) {
                ((struct udphdr *)l4)->source = htons(e->ext_port);
            } /* ICMP keep id */
            ip->ip_sum = 0;
            ip->ip_sum = checksum(ip, ip->ip_hl * 4);

            size_t l4len = ntohs(ip->ip_len) - ip->ip_hl * 4;
            if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {
                uint16_t cks = l4_checksum(ip, l4, l4len);
                if (ip->ip_p == IPPROTO_TCP)
                    ((struct tcphdr *)l4)->check = cks;
                else
                    ((struct udphdr *)l4)->check = cks;
            } else if (ip->ip_p == IPPROTO_ICMP) {
                ((struct icmphdr *)l4)->checksum = checksum(l4, l4len);
            }

            int hdr_len = sizeof(*eth) + ip->ip_hl * 4 + hdr_add;
            int pay_len = n - hdr_len;
            // if(pay_len>0)dump_payload(buf+hdr_len,pay_len);
            if (send_out_via_s1(raw_ext, (uint8_t *)ip, n - sizeof(struct ether_header), (char *)gw_mac, ext_if) == -1)
                perror("send ext");
        }

        /* -------- external → internal -------- */
        if (FD_ISSET(raw_ext, &rd)) {
            ssize_t n = recv(raw_ext, buf, BUF_SZ, 0);
            if (n <= 0) {
                continue;
            }
            struct ether_header *eth = (void *)buf;

            if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
                continue;
            }
            struct ip *ip = (void *)(buf + sizeof(*eth));
            if (ip->ip_src.s_addr == ext_if_info.ip_addr.s_addr) {
                    continue;
            }

            void *l4 = (unsigned char *)ip + ip->ip_hl * 4;
            uint16_t id_or_port = 0;
            size_t hdr_add = 0;
            if (ip->ip_p == IPPROTO_TCP) {
                struct tcphdr *t = l4;
                id_or_port = ntohs(t->dest);
                hdr_add = t->doff * 4;
                t->check = 0;
            } else if (ip->ip_p == IPPROTO_UDP) {
                struct udphdr *u = l4;
                id_or_port = ntohs(u->dest);
                hdr_add = sizeof(struct udphdr);
                u->check = 0;
            } else if (ip->ip_p == IPPROTO_ICMP) {
                struct icmphdr *c = l4;
                id_or_port = ntohs(c->un.echo.id);
                hdr_add = sizeof(struct icmphdr);
                c->checksum = 0;
            } else
                continue;

            // printf("fidning NAT entry   ------------------------\n");
            // print_nat_table();
            // printf("nat_lookup arguments:\n");
            // printf("  IP dst: %s\n", inet_ntoa(ip->ip_dst.s_addr));
            // printf("  Port/ID: %u\n", ntohs(id_or_port));
            // printf("  Protocol: %u\n", ip->ip_p);
            struct nat_entry *e = nat_lookup(ip->ip_dst.s_addr, id_or_port, ip->ip_p, 1);

            if (!e) {
                // printf("cannot find entry\n");
                continue;
            }
            // print_tcpdump_packet(ip, "eth0");

            e->ts = time(NULL);
            ip->ip_dst.s_addr = e->int_ip;
            if (ip->ip_p == IPPROTO_TCP) {
                ((struct tcphdr *)l4)->dest = htons(e->int_port);
            } else if (ip->ip_p == IPPROTO_UDP) {
                ((struct udphdr *)l4)->dest = htons(e->int_port);
            } /* ICMP keep id */

            ip->ip_sum = 0;
            ip->ip_sum = checksum(ip, ip->ip_hl * 4);
            size_t l4len = ntohs(ip->ip_len) - ip->ip_hl * 4;
            if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {
                uint16_t cks = l4_checksum(ip, l4, l4len);
                if (ip->ip_p == IPPROTO_TCP) {
                    ((struct tcphdr *)l4)->check = cks;
                } else
                    ((struct udphdr *)l4)->check = cks;
            } else if (ip->ip_p == IPPROTO_ICMP) {
                ((struct icmphdr *)l4)->checksum = checksum(l4, l4len);
            }

            int hdr_len = sizeof(*eth) + ip->ip_hl * 4 + hdr_add;
            int pay_len = n - hdr_len;
            // if(pay_len>0)dump_payload(buf+hdr_len,pay_len);
            struct in_addr host_ip;
            host_ip.s_addr = e->int_ip;
            uint8_t host_mac[6];
            // printf("host IP = %s\n", inet_ntoa(host_ip));

            if (get_mac_from_arp(e->int_ip, host_mac) == -1) {
                fprintf(stderr, "Gateway %s (%s) not in ARP cache\n",
                        int_if, inet_ntoa(host_ip));
                return 1;
            }

            // send to the dest
            if (send_out_via_s1(raw_int, (uint8_t *)ip, n - sizeof(struct ether_header), (char *)host_mac, int_if) == -1)
                perror("send int");
        }
    }
    cleanup(0);
    return 0;
}

