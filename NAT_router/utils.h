#ifndef __UTILS_H
#define __UTILS_H

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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BUF_SZ 65536


uint16_t checksum(void *vdata, size_t len);
uint16_t l4_checksum(struct ip *iph, void *l4, size_t len);
uint16_t validate_udp_checksum(struct ip *iph, struct udphdr *udph, uint8_t *payload, size_t payload_len);

int create_raw(const char *ifname);
uint32_t iface_ip(const char *ifname);

int send_out_via_s1(int fd_s1, const uint8_t *ip_pkt, size_t ip_len, const char *dest_mac, const char *iface);
void fragment_and_send(int sock, struct ip *ip, struct sockaddr_in dst, int mtu);
void send_icmp_frag_needed(int sock, struct ip *orig_ip, struct sockaddr_in dst, int mtu);

int get_iface_mac(const char *ifname, uint8_t mac[6]);

int mac_bin2str(const uint8_t mac[6], char *str, size_t buflen);
int mac_str2bin(const char *str, uint8_t mac[6]);

int get_mac_from_arp(uint32_t ip_le, uint8_t mac[6]);
int get_default_gw(const char *iface_out, size_t iflen, uint32_t *gw_ip);


// Define a structure to hold interface information
typedef struct interface_info {
	char name[IFNAMSIZ];             // Interface name, e.g., "eth0"
	struct in_addr ip_addr;          // IP address
	struct in_addr netmask;          // Subnet mask
	struct in_addr broadcast;        // Broadcast address (if available)
	unsigned char hw_addr[6];        // Hardware (MAC) address (binary)
	char hw_addr_str[18];            // Hardware address as a human-readable string
	int mtu;
} interface_info;
int get_interface_info(const char *ifname, interface_info *info);


int is_host_address(uint32_t ip, interface_info *info);
int is_public_address(uint32_t ip);

#endif