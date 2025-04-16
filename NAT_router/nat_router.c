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
#include <pthread.h>

#include "table.h"
#include "debug_print.h"
#include "utils.h"

volatile sig_atomic_t running = 1;

interface_info int_if_info, ext_if_info;
int raw_int = -1, raw_ext = -1;
uint8_t gw_mac[6];


/* Admin thread function to handle NAT table requests via UDP */
void *admin_thread_func(void *arg) {
    int admin_fd;
    struct sockaddr_in admin_addr, client_addr;
    socklen_t client_addr_len;
    char admin_buf[1024];
    char nat_table_str[16384];
    admin_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (admin_fd < 0) {
        perror("Admin thread: socket creation failed");
        pthread_exit(NULL);
    }

    memset(&admin_addr, 0, sizeof(admin_addr));
    admin_addr.sin_family = AF_INET;
    admin_addr.sin_addr.s_addr = INADDR_ANY;
    admin_addr.sin_port = htons(9999);

    if (bind(admin_fd, (struct sockaddr *)&admin_addr, sizeof(admin_addr)) < 0) {
        perror("Admin thread: bind failed");
        close(admin_fd);
        pthread_exit(NULL);
    }

    printf("Admin thread: listening on port 9999...\n");
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(admin_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (running) {
        client_addr_len = sizeof(client_addr);
        int n = recvfrom(admin_fd, admin_buf, sizeof(admin_buf) - 1, 0,
                           (struct sockaddr *)&client_addr, &client_addr_len);
        if (n < 0) {
            // perror("Admin thread: recvfrom failed");
            continue;
        }
        admin_buf[n] = '\0';
        printf("Admin thread: received command: %s\n", admin_buf);
        if (strcmp(admin_buf, "PRINT_NAT_TABLE") == 0) {
            memset(nat_table_str, 0, sizeof(nat_table_str));
            get_nat_table_string(nat_table_str, sizeof(nat_table_str));
            if (sendto(admin_fd, nat_table_str, strlen(nat_table_str), 0,
                       (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("Admin thread: sendto failed");
            }
        }
    }

    close(admin_fd);
    pthread_exit(NULL);
}

void* internal_thread_func(void *arg) {
    unsigned char buf[BUF_SZ];
    while (running) {
        ssize_t n = recv(raw_int, buf, BUF_SZ, 0);
        if (n <= 0) continue;
        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            continue;
        struct ip *ip = (struct ip *)(buf + sizeof(*eth));
        if (checksum(ip, ip->ip_hl * 4) != 0) {
            // fprintf(stderr, "Invalid IP checksum\n");
            continue;
        }
        if (is_host_address(ntohl(ip->ip_src.s_addr), &int_if_info) == 0) {
            // fprintf(stderr, "Not a host address\n");
            continue;
        }
        if (is_public_address(ntohl(ip->ip_dst.s_addr)) == 0) {
            // fprintf(stderr, "Not a public address\n");
            continue;
        }
        if (!(ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP || ip->ip_p == IPPROTO_ICMP)) {
            // fprintf(stderr, "Not TCP/UDP/ICMP\n");
            continue;
        }
        
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
            id_or_port = ntohs(*(uint16_t *)(l4 + 4));
            hdr_add = sizeof(struct icmphdr);
            icmp->checksum = 0;
        }
        
        struct nat_entry *e = nat_lookup(ip->ip_src.s_addr, id_or_port, ip->ip_p, 0);
        if (!e) {
            e = nat_create(ip->ip_src.s_addr, id_or_port, ext_if_info.ip_addr.s_addr, ip->ip_p);
        }
        e->ts = time(NULL);
        ip->ip_src.s_addr = e->ext_ip;
        if (ip->ip_p == IPPROTO_TCP) {
            ((struct tcphdr *)l4)->source = htons(e->ext_port);
        } else if (ip->ip_p == IPPROTO_UDP) {
            ((struct udphdr *)l4)->source = htons(e->ext_port);
        }
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
        
        if (send_out_via_s1(raw_ext, (uint8_t *)ip, n - sizeof(struct ether_header),
            (char *)gw_mac, ext_if_info.name) == -1)
            perror("send ext");
    }
    return NULL;
}

void* external_thread_func(void *arg) {
    unsigned char buf[BUF_SZ];
    while (running) {
        ssize_t n = recv(raw_ext, buf, BUF_SZ, 0);
        if (n <= 0) continue;
        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            continue;
        struct ip *ip = (struct ip *)(buf + sizeof(*eth));

        // if (ip->ip_src.s_addr == ext_if_info.ip_addr.s_addr) {
        //     fprintf(stderr, "Packet from external interface\n");
        //     continue;        
        // }
        if (checksum(ip, ip->ip_hl * 4) != 0) {
            // fprintf(stderr, "Invalid IP checksum\n");
            continue;
        }
        if (is_public_address(ntohl(ip->ip_src.s_addr)) == 0) {
            // fprintf(stderr, "Not a public address\n");
            continue;
        }
        if (ip->ip_dst.s_addr != ext_if_info.ip_addr.s_addr) {
            // fprintf(stderr, "Invalid dst address\n");
            continue;
        }
        if (!(ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP || ip->ip_p == IPPROTO_ICMP)) {
            // fprintf(stderr, "Not TCP/UDP/ICMP\n");
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
        } else {
            continue;
        }
        
        struct nat_entry *e = nat_lookup(ip->ip_dst.s_addr, id_or_port, ip->ip_p, 1);
        if (!e)
            continue;
        e->ts = time(NULL);
        ip->ip_dst.s_addr = e->int_ip;
        if (ip->ip_p == IPPROTO_TCP) {
            ((struct tcphdr *)l4)->dest = htons(e->int_port);
        } else if (ip->ip_p == IPPROTO_UDP) {
            ((struct udphdr *)l4)->dest = htons(e->int_port);
        }
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
        
        struct in_addr host_ip;
        host_ip.s_addr = e->int_ip;
        uint8_t host_mac[6];
        if (get_mac_from_arp(e->int_ip, host_mac) == -1) {
            fprintf(stderr, "Interface %s (%s) not in ARP cache\n", int_if_info.name, inet_ntoa(host_ip));
            continue;
        }
        
        if (send_out_via_s1(raw_int, (uint8_t *)ip, n - sizeof(struct ether_header),
            (char *)host_mac, int_if_info.name) == -1)
            perror("send int");
    }
    return NULL;
}

void* nat_gc_thread_func(void *arg) {
    while (running) {
        nat_gc();
        sleep(1);
    }
    return NULL;
}

void cleanup(int sig) {
    running = 0;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <int_if> <ext_if>\n", argv[0]);
        return 1;
    }
    srand(time(NULL));
    
    raw_int = create_raw(argv[1]);
    raw_ext = create_raw(argv[2]);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(raw_int, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(raw_ext, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    puts("[+] User‑space NAT running… Ctrl‑C to quit.\n");
    
    if (get_interface_info(argv[1], &int_if_info) == -1) {
        fprintf(stderr, "Failed to get info for interface %s\n", argv[1]);
        return 1;
    } else {
        printf("Internal interface: %s\n", int_if_info.name);
        printf("Internal IP: %s\n", inet_ntoa(int_if_info.ip_addr));
        printf("Internal MAC: %s\n", int_if_info.hw_addr_str);
        printf("Internal netmask: %s\n", inet_ntoa(int_if_info.netmask));
        printf("Internal broadcast: %s\n", inet_ntoa(int_if_info.broadcast));
    }

    if (get_interface_info(argv[2], &ext_if_info) == -1) {
        fprintf(stderr, "Failed to get info for interface %s\n", argv[2]);
        return 1;
    } else {
        printf("External interface: %s\n", ext_if_info.name);
        printf("External IP: %s\n", inet_ntoa(ext_if_info.ip_addr));
        printf("External MAC: %s\n", ext_if_info.hw_addr_str);
        printf("External netmask: %s\n", inet_ntoa(ext_if_info.netmask));
        printf("External broadcast: %s\n", inet_ntoa(ext_if_info.broadcast));
    }

    // get default gateway ip
    uint32_t gw_ip_le;
    char gw_mac_str[40];

    if (get_default_gw(ext_if_info.name, sizeof(ext_if_info.name), &gw_ip_le) == -1) {
        fprintf(stderr, "No default gateway found\n");
        return 1;
    }

    // get default gateway mac
    struct in_addr gw_ip;
    gw_ip.s_addr = gw_ip_le;
    printf("Gateway IP = %s\n", inet_ntoa(gw_ip));

    if (get_mac_from_arp(gw_ip_le, gw_mac) == -1) {
        fprintf(stderr, "Gateway %s (%s) not in ARP cache\n",
            ext_if_info.name, inet_ntoa(gw_ip));
        return 1;
    }
    // just for debugging
    mac_bin2str(gw_mac, gw_mac_str, sizeof(gw_mac_str));
    printf("Gateway MAC = %s -------------------\n", gw_mac_str);

    pthread_t internal_thread, external_thread, gc_thread, admin_thread;


    if (pthread_create(&admin_thread, NULL, admin_thread_func, NULL) != 0) {
        perror("Failed to create admin thread");
        exit(EXIT_FAILURE);
    }
    printf("Admin thread spawned.\n");


    if (pthread_create(&internal_thread, NULL, internal_thread_func, NULL) != 0) {
        perror("Failed to create internal thread");
        exit(EXIT_FAILURE);
    }
    printf("Outward translation thread spawned.\n");

    if (pthread_create(&external_thread, NULL, external_thread_func, NULL) != 0) {
        perror("Failed to create external thread");
        exit(EXIT_FAILURE);
    }
    printf("Inward translation thread spawned.\n");

    if (pthread_create(&gc_thread, NULL, nat_gc_thread_func, NULL) != 0) {
        perror("Failed to create NAT GC thread");
        exit(EXIT_FAILURE);
    }
    printf("NAT garbage cleaning thread spawned.\n");

    pthread_join(admin_thread, NULL);
    pthread_join(internal_thread, NULL);
    pthread_join(external_thread, NULL);
    pthread_join(gc_thread, NULL);


    if (raw_int != -1)
        close(raw_int);
    if (raw_ext != -1)
        close(raw_ext);
    puts("\n[+] NAT stopped.");

    return 0;
}
