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

int get_interface_info(const char *ifname, interface_info *info) {
    if (!info) {
        perror("malloc");
        return -1;
    }
    // Copy the interface name into the structure
    strncpy(info->name, ifname, IFNAMSIZ - 1);
    info->name[IFNAMSIZ - 1] = '\0';

    // Open a socket for ioctl calls
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        free(info);
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Get IP address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        free(info);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    info->ip_addr = sin->sin_addr;

    // Get subnet mask
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == -1) {
        perror("ioctl SIOCGIFNETMASK");
        close(sockfd);
        free(info);
        return -1;
    }
    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    info->netmask = sin->sin_addr;

    // Get broadcast address (if available)
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFBRDADDR, &ifr) == -1) {
        // Broadcast address may not be defined, so set to 0 if not available
        info->broadcast.s_addr = 0;
    } else {
        sin = (struct sockaddr_in *)&ifr.ifr_addr;
        info->broadcast = sin->sin_addr;
    }

    // Get MTU
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFMTU, &ifr) == -1) {
        perror("ioctl SIOCGIFMTU");
        close(sockfd);
        free(info);
        return -1;
    }
    info->mtu = ifr.ifr_mtu;

    // Get hardware (MAC) address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        free(info);
        return -1;
    }
    memcpy(info->hw_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);

    // Format the MAC address as a human‑readable string ("AA:BB:CC:DD:EE:FF")
    snprintf(info->hw_addr_str, sizeof(info->hw_addr_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             info->hw_addr[0], info->hw_addr[1], info->hw_addr[2],
             info->hw_addr[3], info->hw_addr[4], info->hw_addr[5]);

    return 0;
}

int is_host_address(uint32_t ip, interface_info *info) {
    uint32_t gateway_ip = ntohl(info->ip_addr.s_addr);
    uint32_t mask = ntohl(info->netmask.s_addr);
    uint32_t broadcast = ntohl(info->broadcast.s_addr);

    printf("DEBUG: is_host_address() called with: ip=0x%08x, gateway_ip=0x%08x, mask=0x%08x, broadcast=0x%08x\n", ip, gateway_ip, mask, broadcast);

    if ((ip & mask) != (gateway_ip & mask)) {
        printf("DEBUG: ip & mask (0x%08x) != gateway_ip & mask (0x%08x), returning 0\n", ip & mask, gateway_ip & mask);
        return 0;
    }

    if (ip == gateway_ip) {
        printf("DEBUG: ip equals gateway_ip (0x%08x), returning 0\n", gateway_ip);
        return 0;
    }

    if (ip == (gateway_ip & mask)) {
        printf("DEBUG: ip equals network address (gateway_ip & mask = 0x%08x), returning 0\n", (gateway_ip & mask));
        return 0;
    }

    if (broadcast != 0 && ip == broadcast) {
        printf("DEBUG: ip equals broadcast (0x%08x), returning 0\n", broadcast);
        return 0;
    }

    printf("DEBUG: ip is a valid host address, returning 1\n");
    return 1;
}

#include "utils.h"

int is_public_address(uint32_t ip) {
    // Assumes ip is in host byte order.
    uint8_t a = ip >> 24;
    uint8_t b = (ip >> 16) & 0xff;
    uint8_t c = (ip >> 8) & 0xff;
    
    // 0.0.0.0/8 (unspecified)
    if (a == 0) return 0;
    
    // Loopback: 127.0.0.0/8
    if (a == 127) return 0;
    
    // Private network: 10.0.0.0/8
    if (a == 10) return 0;
    
    // Private network: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (a == 172 && (b >= 16 && b <= 31)) return 0;
    
    // Private network: 192.168.0.0/16
    if (a == 192 && b == 168) return 0;
    
    // Link-local: 169.254.0.0/16
    if (a == 169 && b == 254) return 0;
    
    // Carrier-Grade NAT (CGNAT): 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    if (a == 100 && (b >= 64 && b <= 127)) return 0;
    
    // Reserved for IETF protocols: 192.0.0.0/24 (includes some test ranges)
    if (a == 192 && b == 0) return 0;
    
    // Benchmarking addresses: 198.18.0.0/15 (198.18.0.0 - 198.19.255.255)
    if (a == 198 && (b == 18 || b == 19)) return 0;
    
    // Test-Net (documentation): 198.51.100.0/24
    if (a == 198 && b == 51 && c == 100) return 0;
    
    // Test-Net (documentation): 203.0.113.0/24
    if (a == 203 && b == 0 && c == 113) return 0;
    
    // Multicast: 224.0.0.0/4
    if (a >= 224 && a <= 239) return 0;
    
    // Reserved or future use: 240.0.0.0/4 and the broadcast address 255.255.255.255
    if (a >= 240) return 0;
    if (ip == 0xFFFFFFFF) return 0;
    
    // If none of the above conditions are met, the IP address is public.
    return 1;
}


void fragment_and_send(int sock, struct ip *ip, struct sockaddr_in dst, int mtu) {
    int hdr_len    = ip->ip_hl * 4;
    int total_len  = ntohs(ip->ip_len);
    int payload_len= total_len - hdr_len;
    int max_data   = (mtu - hdr_len) & ~7;  // must be 8‑byte aligned
    uint16_t orig_off = ntohs(ip->ip_off) & IP_DF;  // preserve DF flag
    uint8_t *orig_pkt = (uint8_t*)ip;
    uint8_t *orig_payload = orig_pkt + hdr_len;

    int offset = 0;
    while (payload_len > 0) {
        int this_data = payload_len > max_data ? max_data : payload_len;
        // build a local fragment buffer
        uint8_t *frag = malloc(hdr_len + this_data);
        memcpy(frag, orig_pkt, hdr_len);               // copy IP header
        memcpy(frag+hdr_len, orig_payload+offset, this_data); // copy correct slice

        struct ip *fip = (struct ip*)frag;
        fip->ip_len = htons(hdr_len + this_data);
        fip->ip_off = htons(orig_off | ((offset>>3)&IP_OFFMASK) |
                            (payload_len>max_data ? IP_MF : 0));
        fip->ip_sum = 0;
        fip->ip_sum = checksum(fip, hdr_len);

        sendto(sock, frag, hdr_len + this_data, 0,
               (struct sockaddr*)&dst, sizeof(dst));
        free(frag);

        offset      += this_data;
        payload_len -= this_data;
    }
}

void send_icmp_frag_needed(int sock, struct ip *orig_ip, struct sockaddr_in dst, int mtu) {
    // Build ICMP Destination Unreachable (Type 3, Code 4)
    uint8_t buf[1280];
    struct ip *ip_hdr = (struct ip*)buf;
    struct icmphdr *icmp = (struct icmphdr*)(buf + sizeof(*ip_hdr));
    // prepare outer IP header
    ip_hdr->ip_hl = sizeof(*ip_hdr) >> 2;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(*ip_hdr) + sizeof(*icmp) + sizeof(struct ip) + 8);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_src = orig_ip->ip_dst;
    ip_hdr->ip_dst = orig_ip->ip_src;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = checksum(ip_hdr, ip_hdr->ip_hl * 4);
    // prepare ICMP header
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_FRAG_NEEDED;
    icmp->un.frag.mtu = htons( mtu );
    memcpy(buf + sizeof(*ip_hdr) + sizeof(*icmp), orig_ip, (orig_ip->ip_hl * 4) + 8);
    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, sizeof(*icmp) + (orig_ip->ip_hl * 4) + 8);
    sendto(sock, buf, ntohs(ip_hdr->ip_len), 0, (struct sockaddr*)&dst, sizeof(dst));
}