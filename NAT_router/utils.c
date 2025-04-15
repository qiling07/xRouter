#include "utils.h"

/* ---------------- helpers ---------------- */

uint16_t checksum(void *vdata, size_t len) {
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

uint16_t l4_checksum(struct ip *iph, void *l4, size_t len) {
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

int create_raw(const char *ifname) {
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
uint32_t iface_ip(const char *ifname) {
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

    // print_tcpdump_packet(ip_pkt, iface);

    if (sendto(fd_s1, frame, frame_len, 0,
               (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
        perror("sendto s1");
        return -1;
    }
    return 0;
}

int get_iface_mac(const char *ifname, uint8_t mac[6]) {
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

int mac_str2bin(const char *str, uint8_t mac[6]) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2],
                  &mac[3], &mac[4], &mac[5]) == 6
               ? 0
               : -1;
}

int get_default_gw(const char *iface_out, size_t iflen, uint32_t *gw_ip) {
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



int get_mac_from_arp(uint32_t ip_le, uint8_t mac[6]) {
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


