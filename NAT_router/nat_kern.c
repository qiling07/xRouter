#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>  // for offsetof
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <stdint.h>
#include <linux/icmp.h>



#include "nat_kern.h"

#define NAT_TABLE_SIZE 8092

// single hash map for all NAT entries
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key, struct nat_key);
    __type(value, struct nat_val);
} nat_map SEC(".maps");

// devmap for redirecting packets across interfaces
// index 0 → eth0, index 1 → eth1
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size,   sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 2);
} ifindex_map SEC(".maps");


// Checksum utilities
__attribute__((__always_inline__))
static inline __u16 csum_fold_helper(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

// Update checksum following RFC 1624 (Eqn. 3): https://tools.ietf.org/html/rfc1624
//     HC' = ~(~HC + ~m + m')
// Where :
//   HC  - old checksum in header
//   HC' - new checksum in header
//   m   - old value
//   m'  - new value
__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC 
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result ! 
    *csum = csum_fold_helper(*csum);
}

int is_host_address(uint32_t ip, uint32_t gateway_ip, uint32_t mask, uint32_t broadcast) {
    if ((ip & mask) != (gateway_ip & mask)) return 0;
    if (ip == gateway_ip) return 0;
    if (ip == (gateway_ip & mask)) return 0;
    if (broadcast != 0 && ip == broadcast) return 0;

    return 1;
}

// inbound: pkt arrives on eth0 → lookup on (dst_ip, dst_port) → SNAT → redirect to eth1
SEC("xdp")
int xdp_nat_out(struct xdp_md *ctx)
{
    unsigned int data_start = ctx->data;
    unsigned int data_end = ctx->data_end;
    if (data_start >= data_end) return XDP_PASS;

    void *buf = (void *)data_start;
    if (buf + 1 > (void*)data_end) return XDP_PASS;

    long n = data_end - (unsigned long)buf;
	if (n > 1500) return XDP_PASS;						// hardcoded

	// filter out IP packets
    struct ethhdr *eth = (struct ethhdr *)buf;
    if ((void*)eth + sizeof(*eth) > (void*)data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)((uintptr_t)eth + sizeof(*eth));
    if ((void*)ip+sizeof(*ip) > (void*)data_end) return XDP_PASS;
    if (ip->ihl * 4 != 20) return XDP_PASS;
    if (is_host_address(bpf_ntohl(ip->saddr), 0x0a0a0103, 0xffffff00, 0x0a0a01ff) == 0) 	// hardcoded
        return XDP_PASS;
        
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char*)ip + sizeof(*ip));
        if ((void*)tcp + sizeof(*tcp) > (void*)data_end) return XDP_PASS;
        
        // extracting key fields
        uint32_t src_ip = bpf_ntohl(ip->saddr);
        uint32_t dst_ip = bpf_ntohl(ip->daddr);
        uint16_t src_port = bpf_ntohs(tcp->source);
        uint16_t dst_port = bpf_ntohs(tcp->dest);
        int is_tcp_fin = tcp->fin;
        int is_tcp_ack = tcp->ack;
        int is_tcp_rst = tcp->rst;

        // let userspace nat handle tcp disconnetion
        if (is_tcp_fin || is_tcp_rst) return XDP_PASS;
        

        // Build BPF key in fixed 16-byte stack array to satisfy verifier
        __u64 key_buf[2];
        key_buf[0] = src_ip;
        key_buf[1] = ((__u64)src_port << 32) | IPPROTO_TCP;
        struct nat_val *v = bpf_map_lookup_elem(&nat_map, key_buf);
        if (!v)
            return XDP_PASS;

        return XDP_PASS;

        __u64 now = bpf_ktime_get_ns() / 1000000000;
        v->last_used = now;

        // translation: src_ip -> ext_ip, src_port -> ext_port
        ip->saddr = bpf_htonl(v->ip);
        update_csum(&ip->check, bpf_htonl(src_ip), ip->saddr);
        tcp->source = bpf_htons(v->port);
        update_csum(&tcp->check, bpf_htons(src_port), tcp->source);

        return bpf_redirect_map(&ifindex_map, 0, 0);
    }
    else if (ip->protocol == IPPROTO_UDP) {
        return XDP_PASS;
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        return XDP_PASS;
    } else {
        return XDP_PASS;
    }
}

// inbound: pkt arrives on eth0 → lookup on (dst_port) → DNAT → redirect to eth1
SEC("xdp")
int xdp_nat_in(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
