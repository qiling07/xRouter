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

#define BUF_SZ 65536
#define NAT_TTL 120 // seconds

/* ---------------- NAT table ---------------- */
struct nat_entry {
    uint32_t int_ip;   // internal host IP
    uint16_t int_port; // TCP/UDP port  or  ICMP identifier
    uint32_t ext_ip;   // external iface IP (SNAT)
    uint16_t ext_port; // translated port / identifier
    uint8_t proto;     // IPPROTO_TCP / UDP / ICMP
    time_t ts;         // last activity
    struct nat_entry *next;
};

static uint32_t ext_if_ip; // network‑order
static uint32_t int_if_ip;

static uint16_t random_port() { return (rand() % (65535 - 49152)) + 49152; }
static const char *proto_name(uint8_t p);
static struct nat_entry *nat_head = NULL;

static struct nat_entry *nat_lookup(uint32_t ip, uint16_t port, uint8_t proto, int reverse) {
    for (struct nat_entry *e = nat_head; e; e = e->next) {
        if (!reverse && e->int_ip == ip && e->int_port == port && e->proto == proto)
            return e;
        if (reverse && e->ext_port == port && e->proto == proto)
            return e;
    }
    return NULL;
}
int is_ext_port_taken(uint16_t ext_port, uint8_t proto) {
    for (struct nat_entry *e = nat_head; e; e = e->next) {
        if (e->proto == proto && e->ext_port == ext_port) {
            return 1;
        }
    }
    return 0;
}
static struct nat_entry *nat_create(uint32_t int_ip, uint16_t int_port, uint8_t proto) {
    struct nat_entry *e = (struct nat_entry *)calloc(1, sizeof(*e));
    e->int_ip = int_ip;
    e->int_port = int_port;
    e->ext_ip = ext_if_ip;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        uint16_t port;
        do {
            port = random_port();
        } while (is_ext_port_taken(port, proto));
        e->ext_port = port;
    } else {
        e->ext_port = int_port;
    }

    e->proto = proto;
    e->ts = time(NULL);

    e->next = nat_head;
    nat_head = e;
    return e;
}

static void nat_gc() {
    time_t now = time(NULL);
    struct nat_entry **pp = &nat_head;
    while (*pp) {
        if (now - (*pp)->ts > NAT_TTL) {
            struct nat_entry *old = *pp;
            *pp = old->next;
            free(old);
        } else {
            pp = &(*pp)->next;
        }
    }
}
void print_nat_table() {}

/* ---------------- helpers ---------------- */

static uint16_t checksum(void *vdata, size_t len) {
    uint32_t acc = 0;
    uint16_t *d = (uint16_t *)vdata;
    for (; len > 1; len -= 2)
        acc += *d++;
    if (len)
        acc += *(uint8_t *)d;
    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);
    return (~acc);
}

static uint16_t l4_checksum(struct ip *iph, void *l4, size_t len) {
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t l4len;
    } __attribute__((packed)) pseudo;
    pseudo.src = iph->ip_src.s_addr;
    pseudo.dst = iph->ip_dst.s_addr;
    pseudo.zero = 0;
    pseudo.proto = iph->ip_p;
    pseudo.l4len = htons(len);

    uint32_t acc = 0;
    uint16_t *p = (uint16_t *)&pseudo;
    for (size_t i = 0; i < sizeof(pseudo) / 2; ++i)
        acc += *p++;
    p = (uint16_t *)l4;
    for (; len > 1; len -= 2)
        acc += *p++;
    if (len)
        acc += *(uint8_t *)p;
    while (acc >> 16)
        acc = (acc & 0xFFFF) + (acc >> 16);

    return (~acc);
}

/* ---------------- raw sockets ---------------- */
static int raw_int = -1, raw_ext = -1;
static int create_raw(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket");
        exit(1);
    }
    struct sockaddr_ll s = {0};
    s.sll_family = AF_PACKET;
    s.sll_ifindex = if_nametoindex(ifname);
    s.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&s, sizeof(s)) == -1) {
        perror("bind");
        exit(1);
    }
    return fd;
}
static uint32_t iface_ip(const char *ifname) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        exit(1);
    }
    close(s);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

/* ---------------- payload dump ---------------- */
static void dump_payload(const unsigned char *d, int len) {
    int n = len > 256 ? 256 : len;
    printf("    Payload (%d bytes,showing %d):\n    ", len, n);
    for (int i = 0; i < n; ++i)
        printf("%02X ", d[i]);
    printf("\n    ");
    for (int i = 0; i < n; ++i)
        putchar((d[i] >= 32 && d[i] <= 126) ? d[i] : '.');
    putchar('\n');
}

/* ---------------- proto name helper ---------------- */
static const char *proto_name(uint8_t p) {
    switch (p) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "OTH";
    }
}

/* ---------------- cleanup ---------------- */
static void cleanup(int sig) {
    if (raw_int != -1)
        close(raw_int);
    if (raw_ext != -1)
        close(raw_ext);
    puts("\n[+] NAT stopped.");
    exit(0);
}

int send_out_via_s1(int fd_s1,
                    const uint8_t *ip_pkt,
                    size_t ip_len,
                    const char *dest_mac,
                    const char *iface);

static int get_mac_from_arp(uint32_t ip_le, uint8_t mac[6]);
static int get_default_gw(const char *iface_out, size_t iflen, uint32_t *gw_ip);
static int mac_str2bin(const char *str, uint8_t mac[6]);
void dump_eth_ip_udp(const uint8_t *buf, size_t len);
static int mac_bin2str(const uint8_t mac[6], char *str, size_t buflen);
/* ---------------- main ---------------- */
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
    int_if_ip = iface_ip(int_if);
    ext_if_ip = iface_ip(ext_if);

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
            ssize_t n = recv(raw_int, buf, BUF_SZ, 0);
            if (n <= 0) {
                continue;
            }
            struct ether_header *eth = (void *)buf;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
                continue;
            }
            struct ip *ip = (void *)(buf + sizeof(*eth));
            if (ip->ip_src.s_addr == int_if_ip) {
                continue;
            }
            // printf("INT");
            // printf("src=%s ", inet_ntoa(ip->ip_src));
            // printf("dst=%s proto=%s\n", inet_ntoa(ip->ip_dst), proto_name(ip->ip_p));
            // printf("length=%d", ip->ip_hl*4);

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
                e = nat_create(ip->ip_src.s_addr, id_or_port, ip->ip_p);
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
            if (ip->ip_src.s_addr == ext_if_ip) {
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

// handle Ethernet
static int get_iface_mac(const char *ifname, uint8_t mac[6]) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFHWADDR");
        close(s);
        return -1;
    }
    close(s);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int get_default_gw(const char *iface_out, size_t iflen, uint32_t *gw_ip) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        perror("open route");
        return -1;
    }

    char line[256];
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        char iface[IFNAMSIZ];
        unsigned long dest, gateway, flags;
        if (sscanf(line, "%s %lx %lx %lx", iface, &dest, &gateway, &flags) != 4)
            continue;

        if (dest == 0) {
            strncpy(iface_out, iface, iflen);
            *gw_ip = gateway;
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}
static int mac_str2bin(const char *str, uint8_t mac[6]) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6
               ? 0
               : -1;
}
static int mac_bin2str(const uint8_t mac[6], char *str, size_t buflen) {
    if (buflen < 18) /* "AA:BB:CC:DD:EE:FF" + NUL */
        return -1;

    int n = snprintf(str, buflen,
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2],
                     mac[3], mac[4], mac[5]);

    return (n == 17) ? 0 : -1;
}

static int get_mac_from_arp(uint32_t ip_le, uint8_t mac[6]) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) {
        perror("open arp");
        return -1;
    }

    char line[256];
    fgets(line, sizeof(line), f);

    struct in_addr target;
    target.s_addr = ip_le; /* /proc/net/route little endian */

    while (fgets(line, sizeof(line), f)) {
        char ip_str[64], hw_type[8], flags[8], mac_str[32], mask[32], device[32];
        if (sscanf(line, "%63s %7s %7s %31s %31s %31s",
                   ip_str, hw_type, flags, mac_str, mask, device) != 6)
            continue;

        if (strcmp(ip_str, inet_ntoa(target)) == 0) {
            fclose(f);
            return mac_str2bin(mac_str, mac);
        }
    }
    fclose(f);
    return -1;
}

int send_out_via_s1(int fd_s1,
                    const uint8_t *ip_pkt,
                    size_t ip_len,
                    const char *dst_mac,
                    const char *iface) {
    uint8_t src_mac[6];
    if (get_iface_mac(iface, src_mac) == -1)
        return -1;

    uint8_t frame[BUF_SZ];
    struct ether_header *eth = (struct ether_header *)frame;

    memcpy(eth->ether_shost, src_mac, 6);
    memcpy(eth->ether_dhost, dst_mac, 6);
    eth->ether_type = htons(ETH_P_IP);

    memcpy(frame + sizeof(struct ether_header), ip_pkt, ip_len);
    size_t frame_len = sizeof(struct ether_header) + ip_len;

    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = if_nametoindex(iface);
    saddr.sll_halen = 6;
    memcpy(saddr.sll_addr, dst_mac, 6);

    // dump_eth_ip_udp(frame, frame_len);

    if (sendto(fd_s1, frame, frame_len, 0,
               (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        perror("sendto s1");
        return -1;
    }
    return 0;
}
// DEBUG function
void print_payload(const unsigned char *payload, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", payload[i]);
    }
    printf("\n");
}
// DEBUG function
uint16_t validate_udp_checksum(struct ip *iph, struct udphdr *udph, uint8_t *payload, size_t payload_len);

// DEBUG function
void dump_eth_ip_udp(const uint8_t *buf, size_t len) {

    if (len < sizeof(struct ether_header)) {
        puts("Frame too short for Ethernet header");
        return;
    }
    printf("raw payload");
    print_payload((unsigned char *)buf, len);
    /* ---------- Ethernet ------------------------------------------------ */
    const struct ether_header *eth = (const void *)buf;

    printf("Ethernet:  %02X:%02X:%02X:%02X:%02X:%02X  ->  "
           "%02X:%02X:%02X:%02X:%02X:%02X  type 0x%04X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5],
           ntohs(eth->ether_type));

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        puts("Not an IPv4 packet – done.");
        return;
    }

    /* ---------- IPv4 ---------------------------------------------------- */
    if (len < sizeof(struct ether_header) + sizeof(struct ip)) {
        puts("Frame too short for IP header");
        return;
    }

    const struct ip *iph = (const void *)(buf + sizeof(struct ether_header));
    size_t ip_hl = iph->ip_hl * 4;
    if (len < sizeof(struct ether_header) + ip_hl) {
        puts("Truncated IP header");
        return;
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

    printf("IP:        %s  ->  %s  proto=%u  ttl=%u  ip len=%u\n",
           src, dst, iph->ip_p, iph->ip_ttl, ntohs(iph->ip_len));
    printf(" ID: %X  ", iph->ip_id);
    printf("IP checksum: 0x%04X\n", ntohs(iph->ip_sum));
    if (iph->ip_p != IPPROTO_UDP) {
        puts("Not UDP – done.");
        return;
    }

    /* ---------- UDP ----------------------------------------------------- */
    const struct udphdr *udph =
        (const void *)((const uint8_t *)iph + ip_hl);

    if (len < sizeof(struct ether_header) + ip_hl + sizeof(struct udphdr)) {
        puts("Truncated UDP header");
        return;
    }

    printf("UDP:       src_port=%u  dst_port=%u  length=%u  checksum=0x%04X\n",
           ntohs(udph->source), ntohs(udph->dest),
           ntohs(udph->len), ntohs(udph->check));

    const uint8_t *payload = (const uint8_t *)udph + sizeof(struct udphdr);
    size_t paylen = len - (sizeof(struct ether_header) + ip_hl + sizeof(struct udphdr));
    if (paylen) {
        size_t show = paylen > 64 ? 64 : paylen;
        printf("Payload (%zu bytes, first %zu): ", paylen, show);
        for (size_t i = 0; i < show; ++i)
            printf("%02X ", payload[i]);
        putchar('\n');
    }
    // validate
    uint16_t correct_checksum = validate_udp_checksum(iph, udph, payload, paylen);

    if (correct_checksum == 0) {
        printf("Checksum correct\n");
    } else {
        printf("Checksum incorrect, should be: 0x%04X\n", ntohs(correct_checksum));
    }
}

uint16_t validate_udp_checksum(struct ip *iph, struct udphdr *udph, uint8_t *payload, size_t payload_len) {
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } __attribute__((packed)) ph;

    ph.src = iph->ip_src.s_addr;
    ph.dst = iph->ip_dst.s_addr;
    ph.zero = 0;
    ph.proto = IPPROTO_UDP;
    ph.len = udph->len; // UDP header + payload

    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)&ph;

    for (size_t i = 0; i < sizeof(ph) / 2; i++)
        sum += *p++;

    p = (const uint16_t *)udph;
    for (size_t i = 0; i < sizeof(struct udphdr) / 2; i++)
        sum += *p++;

    p = (const uint16_t *)payload;
    size_t plen = payload_len;
    while (plen > 1) {
        sum += *p++;
        plen -= 2;
    }
    if (plen)
        sum += *(const uint8_t *)p;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    if (sum == 0xFFFF || sum == 0x0000)
        return 0;

    return htons(~sum);
}
