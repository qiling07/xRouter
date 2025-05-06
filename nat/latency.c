#include "latency.h"
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <cassert>

// Compute ICMP checksum
static unsigned short icmp_checksum(void *buf, int len) {
    unsigned int sum = 0;
    unsigned short *ptr = buf;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void latency_probe_all(const char *network_cidr, char *out, size_t out_sz) {
    assert(0 && "Unimplemented");

    char netstr[INET_ADDRSTRLEN];
    int prefix;
    if (sscanf(network_cidr, "%15[^/]/%d", netstr, &prefix) != 2 ||
        prefix < 0 || prefix > 32) {
        snprintf(out, out_sz, "Invalid network CIDR: %s\n", network_cidr);
        return;
    }

    struct in_addr net_addr;
    if (inet_pton(AF_INET, netstr, &net_addr) != 1) {
        snprintf(out, out_sz, "Invalid network address: %s\n", netstr);
        return;
    }
    uint32_t net_h = ntohl(net_addr.s_addr);
    uint32_t mask_h = (prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix)));
    uint32_t base_h = net_h & mask_h;
    uint32_t bc_h   = base_h | (~mask_h);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        snprintf(out, out_sz, "Failed to open raw socket\n");
        return;
    }
    struct timeval to = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

    pid_t pid = getpid() & 0xFFFF;
    size_t used = 0;

    for (uint32_t ip_h = base_h + 1; ip_h + 1 < bc_h; ip_h++) {
		struct sockaddr_in dst;
		memset(&dst, 0, sizeof(dst)); // Ensure the structure is zeroed out
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = htonl(ip_h);

        double rtts[10];
        int replies = 0;

        for (int seq = 0; seq < 10; seq++) {
            struct icmp icmphdr = {0};
            icmphdr.icmp_type = ICMP_ECHO;
            icmphdr.icmp_code = 0;
            icmphdr.icmp_id   = pid;
            icmphdr.icmp_seq  = seq;
            icmphdr.icmp_cksum = icmp_checksum(&icmphdr, sizeof(icmphdr));

            struct timeval t1, t2;
            gettimeofday(&t1, NULL);
            sendto(sock, &icmphdr, sizeof(icmphdr), 0,
                   (struct sockaddr*)&dst, sizeof(dst));

            unsigned char buf[1500];
            ssize_t len = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
            gettimeofday(&t2, NULL);
            if (len < 0) continue;

            struct ip *ip_hdr = (struct ip*)buf;
            int ip_len = ip_hdr->ip_hl * 4;
            struct icmp *icmp_r = (struct icmp*)(buf + ip_len);
            if (icmp_r->icmp_type == ICMP_ECHOREPLY &&
                icmp_r->icmp_id == pid &&
                icmp_r->icmp_seq == seq) {
                double ms = (t2.tv_sec - t1.tv_sec) * 1000.0 +
                            (t2.tv_usec - t1.tv_usec) / 1000.0;
                rtts[replies++] = ms;
            }
        }

        char ipbuf[32];
        inet_ntop(AF_INET, &dst.sin_addr, ipbuf, sizeof(ipbuf));

        if (replies == 0) {
            used += snprintf(out + used, out_sz - used,
                             "%s: timeout\n", ipbuf);
        } else {
            double sum = 0, sum2 = 0;
            double mn = rtts[0], mx = rtts[0];
            for (int i = 0; i < replies; i++) {
                double v = rtts[i];
                sum += v;
                sum2 += v * v;
                if (v < mn) mn = v;
                if (v > mx) mx = v;
            }
            double avg = sum / replies;
            double var = (sum2 / replies) - (avg * avg);
            double mdev = var > 0 ? sqrt(var) : 0;

            used += snprintf(out + used, out_sz - used,
                             "%s min=%.3fms avg=%.3fms max=%.3fms mdev=%.3fms\n",
                             ipbuf, mn, avg, mx, mdev);
        }
        if (used + 128 >= out_sz) break;
    }

    close(sock);
}