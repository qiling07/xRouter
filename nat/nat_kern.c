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
static inline void update_csum(__u16 *csum, __be32 old_addr,__be32 new_addr ) {
    __u64 csum_value = *csum;
    // ~HC 
    csum_value = ~csum_value;
    csum_value = csum_value & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    csum_value += tmp;
    // + m
    csum_value += new_addr;
    // then fold and complement result ! 
    *csum = csum_fold_helper(csum_value);
}


__attribute__((__always_inline__))
static inline void ipv4_l4_csum(void *data_start, __u32 data_size,
                                __u64 *csum, struct iphdr *iph) {
  __u32 tmp = 0;
  *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
  *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
  // __builtin_bswap32 equals to htonl()
  tmp = __builtin_bswap32((__u32)(iph->protocol));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  tmp = __builtin_bswap32((__u32)(data_size));
  *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
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
    // bpf_printk("xdp_nat_out: entered\n");
    unsigned int data_start = ctx->data;
    unsigned int data_end = ctx->data_end;
    if (data_start >= data_end) {
        // bpf_printk("xdp_nat_out: no data\n");
        return XDP_PASS;
    }

    void *buf = (void *)data_start;
    if (buf + 1 > (void*)data_end) {
        // bpf_printk("xdp_nat_out: buf too small\n");
        return XDP_PASS;
    }

    long n = data_end - (unsigned long)buf;
    if (n > 1500) {
        // bpf_printk("xdp_nat_out: packet too large\n");
        return XDP_PASS;
    }						// hardcoded

    // filter out IP packets
    struct ethhdr *eth = (struct ethhdr *)buf;
    if ((void*)eth + sizeof(*eth) > (void*)data_end) {
        // bpf_printk("xdp_nat_out: incomplete ethhdr\n");
        return XDP_PASS;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        // bpf_printk("xdp_nat_out: not IPv4 proto %x\n", eth->h_proto);
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)((uintptr_t)eth + sizeof(*eth));
    if ((void*)ip + sizeof(*ip) > (void*)data_end) {
        // bpf_printk("xdp_nat_out: incomplete iphdr\n");
        return XDP_PASS;
    }
    // uint16_t ip_tot_len = bpf_ntohs(ip->tot_len);
    // if (ip_tot_len <= 20) return XDP_PASS;
    // if ((void*)ip + ip_tot_len > (void*)data_end) return XDP_PASS;
    if (ip->ihl * 4 != 20) {
        // bpf_printk("xdp_nat_out: unexpected IHL %d\n", ip->ihl);
        return XDP_PASS;
    }
    if (is_host_address(bpf_ntohl(ip->saddr), 0x0a0a0103, 0xffffff00, 0x0a0a01ff) == 0) { 	// hardcoded
        // bpf_printk("xdp_nat_out: not in subnet or is gateway/broadcast\n");
        return XDP_PASS;
    }
        
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char*)ip + sizeof(*ip));
        if ((void*)tcp + sizeof(*tcp) > (void*)data_end) {
            // bpf_printk("xdp_nat_out: incomplete tcphdr\n");
            return XDP_PASS;
        }

        // extracting key fields
        uint32_t src_ip = bpf_ntohl(ip->saddr);
        uint32_t dst_ip = bpf_ntohl(ip->daddr);
        uint16_t src_port = bpf_ntohs(tcp->source);
        uint16_t dst_port = bpf_ntohs(tcp->dest);
        int is_tcp_fin = tcp->fin;
        int is_tcp_ack = tcp->ack;
        int is_tcp_rst = tcp->rst;

        bpf_printk("xdp_nat_out: TCP packet for %x:%d ->\n", src_ip, src_port);

        // let userspace nat handle tcp disconnetion
        if (is_tcp_fin || is_tcp_rst) return XDP_PASS;

        struct nat_key key = {0};
        key.ip = src_ip;
        key.port = src_port;
        key.proto = IPPROTO_TCP;
        struct nat_val *v = bpf_map_lookup_elem(&nat_map, &key);
        if (!v) {
            bpf_printk("xdp_nat_out: map lookup miss \n");
            return XDP_PASS;
        }


        bpf_printk("xdp_nat_out: map lookup hit\n");
        bpf_printk("%x:%d\n", v->ip, v->port);


        __u64 now = bpf_ktime_get_ns() / 1000000000;
        v->last_used = now;

        // translation: src_ip -> ext_ip, src_port -> ext_port
        ip->saddr = bpf_htonl(v->ip);
        update_csum(&ip->check, bpf_htonl(src_ip), ip->saddr);
        
        tcp->source = bpf_htons(v->port);
        update_csum(&tcp->check, bpf_htonl(src_ip), ip->saddr);
        update_csum(&tcp->check, bpf_htons(src_port), tcp->source);
        // tcp->check = 0;
        // unsigned long long cs = 0;
        // ipv4_l4_csum((void *)tcp, ip_tot_len - 20, &cs, ip);
        // tcp->check = cs;

        bpf_printk("xdp_nat_out: performing FIB lookup\n");
        struct bpf_fib_lookup fib_params;
        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.family	= AF_INET;
		fib_params.tos		= ip->tos;
		fib_params.l4_protocol	= ip->protocol;
		fib_params.tot_len	= bpf_ntohs(ip->tot_len);
		fib_params.ipv4_src	= ip->saddr;
		fib_params.ipv4_dst	= ip->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            bpf_printk("xdp_nat_out: FIB lookup success\n");
            bpf_printk("xdp_nat_out: FIB ifindex=%d\n", fib_params.ifindex);
            bpf_printk("xdp_nat_out: FIB smac=%02x:%02x:%02x\n",
                       fib_params.smac[0], fib_params.smac[1], fib_params.smac[2]);
            bpf_printk("xdp_nat_out: FIB smac=%02x:%02x:%02x\n",
                       fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
            bpf_printk("xdp_nat_out: FIB dmac=%02x:%02x:%02x\n",
                       fib_params.dmac[0], fib_params.dmac[1], fib_params.dmac[2]);
            bpf_printk("xdp_nat_out: FIB dmac=%02x:%02x:%02x\n",
                       fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
            // update Ethernet header
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
            // return bpf_redirect_map(&ifindex_map, fib_params.ifindex, 0);
        } else {
            bpf_printk("xdp_nat_out: FIB lookup failed, rc=%d\n", rc);
            return XDP_PASS;
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((char*)ip + sizeof(*ip));
        if ((void*)udp + sizeof(*udp) > (void*)data_end) {
            return XDP_PASS;
        }

        // extracting key fields
        uint32_t src_ip = bpf_ntohl(ip->saddr);
        uint32_t dst_ip = bpf_ntohl(ip->daddr);
        uint16_t src_port = bpf_ntohs(udp->source);
        uint16_t dst_port = bpf_ntohs(udp->dest);

        struct nat_key key = {0};
        key.ip = src_ip;
        key.port = src_port;
        key.proto = IPPROTO_UDP;
        struct nat_val *v = bpf_map_lookup_elem(&nat_map, &key);
        if (!v) {
            return XDP_PASS;
        }

        __u64 now = bpf_ktime_get_ns() / 1000000000;
        v->last_used = now;

        // translation: src_ip -> ext_ip, src_port -> ext_port
        ip->saddr = bpf_htonl(v->ip);
        update_csum(&ip->check, bpf_htonl(src_ip), ip->saddr);
        
        udp->source = bpf_htons(v->port);
        udp->check = 0;

        struct bpf_fib_lookup fib_params;
        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.family	= AF_INET;
		fib_params.tos		= ip->tos;
		fib_params.l4_protocol	= ip->protocol;
		fib_params.tot_len	= bpf_ntohs(ip->tot_len);
		fib_params.ipv4_src	= ip->saddr;
		fib_params.ipv4_dst	= ip->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
        } else {
            return XDP_PASS;
        }
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
    unsigned int data_start = ctx->data;
    unsigned int data_end = ctx->data_end;
    if (data_start >= data_end) return XDP_PASS;
	if (data_end - data_start > 1500) return XDP_PASS;						// hardcoded

    void *buf = (void *)data_start;
    if (buf + 1 > (void*)data_end) return XDP_PASS;

	// filter out IP packets
    struct ethhdr *eth = (struct ethhdr *)buf;
    if ((void*)eth + sizeof(*eth) > (void*)data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)((uintptr_t)eth + sizeof(*eth));
    if ((void*)ip+sizeof(*ip) > (void*)data_end) return XDP_PASS;
    // uint16_t ip_tot_len = bpf_ntohs(ip->tot_len);
    // if (ip_tot_len <= 20) return XDP_PASS;
    // if ((void*)ip + ip_tot_len > (void*)data_end) return XDP_PASS;
    if (ip->ihl * 4 != 20) return XDP_PASS;
    if (bpf_ntohl(ip->daddr) != 0x806991cf) return XDP_PASS;                // hardcoded 128.105.145.207
    
        
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

        // Print TCP packet info
        bpf_printk("xdp_nat_in: TCP packet -> %x:%d\n", dst_ip, dst_port);

        // let userspace nat handle tcp disconnetion
        if (is_tcp_fin || is_tcp_rst) return XDP_PASS;
        
        // Build BPF key in fixed 16-byte stack array to satisfy verifier
        struct nat_key key = {0};
        key.ip = dst_ip;
        key.port = dst_port;
        key.proto = IPPROTO_TCP;
        struct nat_val *v = bpf_map_lookup_elem(&nat_map, &key);
        if (!v) {
            bpf_printk("xdp_nat_in: map lookup miss\n");
            return XDP_PASS;
        }
        bpf_printk("xdp_nat_in: map lookup hit\n");

        __u64 now = bpf_ktime_get_ns() / 1000000000;
        v->last_used = now;

        // translation: dst_ip -> int_ip, dst_port -> int_port
        ip->daddr = bpf_htonl(v->ip);
        update_csum(&ip->check, bpf_htonl(dst_ip), ip->daddr);

        tcp->dest = bpf_htons(v->port);
        update_csum(&tcp->check, bpf_htonl(dst_ip), ip->daddr);
        update_csum(&tcp->check, bpf_htons(dst_port), tcp->dest);
        // tcp->check = 0;
        // unsigned long long cs = 0;
        // ipv4_l4_csum((void *)tcp, ip_tot_len - 20, &cs, ip);
        // tcp->check = cs;

        bpf_printk("xdp_nat_in: performing FIB lookup\n");
        struct bpf_fib_lookup fib_params;
        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.family	= AF_INET;
		fib_params.tos		= ip->tos;
		fib_params.l4_protocol	= ip->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip->tot_len);
		fib_params.ipv4_src	= ip->saddr;
		fib_params.ipv4_dst	= ip->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            bpf_printk("xdp_nat_in: FIB lookup success\n");
            bpf_printk("xdp_nat_in: FIB ifindex=%d\n", fib_params.ifindex);
            bpf_printk("xdp_nat_in: FIB smac=%02x:%02x:%02x\n",
                       fib_params.smac[0], fib_params.smac[1], fib_params.smac[2]);
            bpf_printk("xdp_nat_in: FIB smac=%02x:%02x:%02x\n",
                       fib_params.smac[3], fib_params.smac[4], fib_params.smac[5]);
            bpf_printk("xdp_nat_in: FIB dmac=%02x:%02x:%02x\n",
                       fib_params.dmac[0], fib_params.dmac[1], fib_params.dmac[2]);
            bpf_printk("xdp_nat_in: FIB dmac=%02x:%02x:%02x\n",
                       fib_params.dmac[3], fib_params.dmac[4], fib_params.dmac[5]);
            // update Ethernet header
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
            // return bpf_redirect_map(&ifindex_map, fib_params.ifindex, 0);
        } else {
            bpf_printk("xdp_nat_in: FIB lookup failed, rc=%d\n", rc);
            return XDP_PASS;
        }
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((char*)ip + sizeof(*ip));
        if ((void*)udp + sizeof(*udp) > (void*)data_end) return XDP_PASS;
        
        // extracting key fields
        uint32_t src_ip = bpf_ntohl(ip->saddr);
        uint32_t dst_ip = bpf_ntohl(ip->daddr);
        uint16_t src_port = bpf_ntohs(udp->source);
        uint16_t dst_port = bpf_ntohs(udp->dest);

        // Build BPF key in fixed 16-byte stack array to satisfy verifier
        struct nat_key key = {0};
        key.ip = dst_ip;
        key.port = dst_port;
        key.proto = IPPROTO_UDP;
        struct nat_val *v = bpf_map_lookup_elem(&nat_map, &key);
        if (!v) {
            return XDP_PASS;
        }

        __u64 now = bpf_ktime_get_ns() / 1000000000;
        v->last_used = now;

        // translation: dst_ip -> int_ip, dst_port -> int_port
        ip->daddr = bpf_htonl(v->ip);
        update_csum(&ip->check, bpf_htonl(dst_ip), ip->daddr);

        udp->dest = bpf_htons(v->port);
        udp->check = 0;

        struct bpf_fib_lookup fib_params;
        __builtin_memset(&fib_params, 0, sizeof(fib_params));
        fib_params.family	= AF_INET;
		fib_params.tos		= ip->tos;
		fib_params.l4_protocol	= ip->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip->tot_len);
		fib_params.ipv4_src	= ip->saddr;
		fib_params.ipv4_dst	= ip->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            return bpf_redirect(fib_params.ifindex, 0);
        } else {
            bpf_printk("xdp_nat_in: FIB lookup failed, rc=%d\n", rc);
            return XDP_PASS;
        }
    }
    else if (ip->protocol == IPPROTO_ICMP) {
        return XDP_PASS;
    } else {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
