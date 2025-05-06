#include "debug_print.h"
#include "utils.h"

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

// DEBUG function
void print_payload(const unsigned char *payload, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", payload[i]);
    }
    printf("\n");
}

/* ---------------- payload dump ---------------- */
void dump_payload(const unsigned char *d, int len) {
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
const char *proto_name(uint8_t p) {
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

void print_tcpdump_packet(void *ip_pkt, const char *iface) {
    struct ip *ip_hdr = (struct ip *)ip_pkt;
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        // Get a pointer to the TCP header
        struct tcphdr *tcp = (struct tcphdr *)((uint8_t *)ip_pkt + (ip_hdr->ip_hl * 4));
        
        // Calculate IP header length and TCP header length in bytes
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        int tcp_hdr_len = tcp->doff * 4;
        
        // Calculate total payload length (if any)
        uint16_t ip_total = ntohs(ip_hdr->ip_len);
        int payload_len = ip_total - ip_hdr_len - tcp_hdr_len;
        
        // Build a string representing TCP flags (F for FIN, S for SYN, R for RST, P for PSH, . for ACK, U for URG)
        char flags[16] = "";
        if (tcp->fin) strcat(flags, "F");
        if (tcp->syn) strcat(flags, "S");
        if (tcp->rst) strcat(flags, "R");
        if (tcp->psh) strcat(flags, "P");
        if (tcp->ack) strcat(flags, ".");
        if (tcp->urg) strcat(flags, "U");
        
        // Obtain current time with microsecond precision
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm tm_info;
        localtime_r(&tv.tv_sec, &tm_info);
        char time_buf[16];
        strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));
        
        // Print in the desired tcpdump-like format:
        // Format: TIMESTAMP IP src_ip.src_port > dst_ip.dst_port: Flags [flags], seq sequence, win window, length payload_len
        fprintf(stdout, "%s.%06ld %s IP %s.%u > %s.%u: Flags [%s], seq %u, win %u, length %d\n",
                time_buf, tv.tv_usec, iface,
                src_ip, ntohs(tcp->source),
                dst_ip, ntohs(tcp->dest),
                flags, ntohl(tcp->seq), ntohs(tcp->window), payload_len);
    } else {
        // Optionally, print a fallback message for non-TCP packets.
        fprintf(stdout, "Non-TCP packet sent on interface %s\n", iface);
    }
    fflush(stdout);
}

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

int mac_bin2str(const uint8_t mac[6], char *str, size_t buflen) {
    if (buflen < 18) /* "AA:BB:CC:DD:EE:FF" + NUL */
        return -1;

    int n = snprintf(str, buflen,
                     "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2],
                     mac[3], mac[4], mac[5]);

    return (n == 17) ? 0 : -1;
}
