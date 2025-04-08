#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <stdint.h>

// Define TCP flags for easier interpretation
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

// Define IPv4 header structure (manually defined)
struct iphdr {
    uint8_t  ihl:4,       // Internet Header Length (4 bits)
             version:4;   // IP version (4 bits, value should be 4 for IPv4)
    uint8_t  tos;         // Type of Service
    uint16_t tot_len;     // Total packet length (header + data)
    uint16_t id;          // Identification
    uint16_t frag_off;    // Fragment offset and flags
    uint8_t  ttl;         // Time to Live
    uint8_t  protocol;    // Upper-layer protocol (e.g., TCP=6, UDP=17)
    uint16_t check;       // Header checksum
    uint32_t saddr;       // Source IP address
    uint32_t daddr;       // Destination IP address
} __attribute__((packed)); // Prevent padding by the compiler

// Define TCP header structure
struct tcphdr {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint32_t seq;         // Sequence number
    uint32_t ack_seq;     // Acknowledgment number
    uint8_t  doff;         // Data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;        // TCP control flags (SYN, ACK, etc.)
    uint16_t window;      // Window size
    uint16_t check;       // Checksum
    uint16_t urg_ptr;     // Urgent pointer
} __attribute__((packed));

// Define UDP header structure
struct udphdr {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint16_t len;         // Length of UDP header and data
    uint16_t check;       // Checksum
} __attribute__((packed));

// Buffer size for receiving packets
#define BUFFER_SIZE 1500

// Print raw payload in hexadecimal format
void print_payload(unsigned char *payload, int len) {
    printf(" pay=");
    for (int i = 0; i < len && i < 128; i++) {
        printf("%02X ", payload[i]);
    }
    printf("\n");
}

int main() {
    // Create a raw socket to capture all packets at the Ethernet layer
    int rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawsock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    struct sockaddr saddr;
    struct ifreq myreq;
    char buffer[BUFFER_SIZE];
    
    // Set interface name (e.g., "enp0s3")
    strncpy(myreq.ifr_name, "enp0s3", IFNAMSIZ);
    
    // Enable promiscuous mode to capture all packets
    if (ioctl(rawsock, SIOCGIFFLAGS, &myreq) == -1) {
        perror("ioctl-get");
        exit(1);
    }
    myreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(rawsock, SIOCSIFFLAGS, &myreq) == -1) {
        perror("ioctl-set");
        exit(1);
    }

    int saddr_len = sizeof(saddr);

    // Loop to continuously capture and process packets
    while (1) {
        // Receive packets from the raw socket
        int len = recvfrom(rawsock, buffer, BUFFER_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
        if (len < 0) {
            perror("recvfrom failed");
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Print raw binary payload
        printf("raw payload:\n");
        print_payload((unsigned char*)buffer, len);

        // Print Ethernet header information
        printf("\nEthernet Header:\n");
        printf("\t|-Source MAC Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("\t|-Destination MAC Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("\t|-Protocol: 0x%04X\n", ntohs(eth->h_proto));

        // Check if the Ethernet payload is an IPv4 packet
        if (ntohs(eth->h_proto) == 0x0800) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            struct in_addr src_ip, dst_ip;
            src_ip.s_addr = ip->saddr;
            dst_ip.s_addr = ip->daddr;

            // Print IP header information
            printf("IP: ttl=%d, len=%d\n", ip->ttl, ntohs(ip->tot_len));
            printf("IP: src=%s ", inet_ntoa(src_ip));
            printf("dst=%s type=",  inet_ntoa(dst_ip));
            printf("ip checksum: 0x%04X", ntohs(ip->check));
            printf(" ID: %X  ", ip->id);

            // Check for TCP protocol
            if (ip->protocol == IPPROTO_TCP) {
                printf("TCP\n");
                struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                
                // Print TCP header info including flags
                printf("TCP: src_port=%d dst_port=%d Flags=",
                       ntohs(tcp->source), ntohs(tcp->dest));
                printf("%s%s%s%s%s%s\n",
                     (tcp->flags & TCP_SYN) ? "SYN, " : "",
                     (tcp->flags & TCP_FIN) ? "FIN, " : "",
                     (tcp->flags & TCP_ACK) ? "ACK, " : "",
                     (tcp->flags & TCP_RST) ? "RST, " : "",
                     (tcp->flags & TCP_URG) ? "URG, " : "",
                     (tcp->flags & TCP_PSH) ? "PSH, " : "");

                // Calculate and print TCP payload
                unsigned char *payload = (unsigned char *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4 + (tcp->doff>>4) * 4);
                int payload_len = len - (sizeof(struct ethhdr) + ip->ihl * 4 + (tcp->doff>>4) * 4);
                print_payload(payload, payload_len);
            } 
            // Check for UDP protocol
            else if (ip->protocol == IPPROTO_UDP) {
                printf("UDP\n");
                struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);
                
                // Print UDP header info
                printf("UDP: src_port=%d dst_port=%d length=%d, checksum=0x%04X",
                       ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len), ntohs(udp->check));

                // Calculate and print UDP payload
                unsigned char *payload = (unsigned char *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr));
                int payload_len = len - (sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr));
                print_payload(payload, payload_len);
            } 
            // Other IP protocols
            else {
                printf("%d\n", ip->protocol);
            }
        }
    }
    return 0;
}
