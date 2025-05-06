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
#include "filter.h"
#include "latency.h"
#include <net/if.h>
#include <sys/ioctl.h>


#define NUM_WORKERS 4

typedef struct job {
    unsigned char *data;
    ssize_t len;
    struct job *next;
} job_t;

typedef struct job_queue {
    job_t *head;
    job_t *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} job_queue_t;

static job_queue_t outbound_queue;
static job_queue_t inbound_queue;


volatile sig_atomic_t running = 1;
interface_info int_if_info, ext_if_info;
int outward_sock = -1;
int inward_sock = -1;

#ifdef USE_EBPF
#include <bpf/libbpf.h>
struct bpf_link *link_out = NULL, *link_in = NULL;
#endif

// sent, received, stored in network byte order
typedef struct {
    uint32_t int_ip;
    uint16_t int_port;
    uint16_t ext_port;
} port_forward_info;        

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
            get_nat_table_string(nat_table_str, sizeof(nat_table_str), 0);
            if (sendto(admin_fd, nat_table_str, strlen(nat_table_str), 0,
                       (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("Admin thread: sendto failed");
            }
        }
        else if (strcmp(admin_buf, "RESET_NAT_TABLE") == 0) {
            // Reset the NAT table
            nat_reset();
            // Send acknowledgment back to client
            const char *reset_msg = "NAT table has been reset";
            if (sendto(admin_fd, reset_msg, strlen(reset_msg), 0,
                       (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("Admin thread: sendto failed");
            }
        }
        else if (strncmp(admin_buf, "ADD_FILTER ", 11) == 0) {
            char domain[DOMAIN_MAX_LEN];
            char ipstr[INET_ADDRSTRLEN];
            int got = sscanf(admin_buf + 11, "%255s %15s", domain, ipstr);
            char resp[100];
            if (got == 2) {
                int r = filter_add(domain, ipstr);
                snprintf(resp, sizeof(resp),
                        r == 0 ? "ADD_FILTER OK\n" : "ADD_FILTER FAILED\n");
            } else {
                snprintf(resp, sizeof(resp),
                        "USAGE: ADD_FILTER <domain> <ip|*>\n");
            }
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strncmp(admin_buf, "DEL_FILTER ", 11) == 0) {
            char domain[DOMAIN_MAX_LEN];
            char ipstr[INET_ADDRSTRLEN];
            int got = sscanf(admin_buf + 11, "%255s %15s", domain, ipstr);
            // printf("parsed domain = '%s', ipstr = '%s', got = %d\n", domain, ipstr, got);
            char resp[100];
            if (got == 2) {
                int r = filter_del(domain, ipstr);
                snprintf(resp, sizeof(resp),
                        r == 0 ? "DEL_FILTER OK\n" : "DEL_FILTER FAILED\n");
            } else {
                // printf("got %d\n", got);
                snprintf(resp, sizeof(resp),
                        "USAGE: DEL_FILTER <domain> <ip|*>\n");
            }
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strcmp(admin_buf, "SHOW_FILTERS") == 0) {
            char listbuf[16384];
            memset(listbuf, 0, sizeof(listbuf));
            filter_list_str(listbuf, sizeof(listbuf));
            sendto(admin_fd, listbuf, strlen(listbuf), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strncmp(admin_buf, "PORT_FORWARD ", 13) == 0) {
            port_forward_info *request = (port_forward_info*)((uintptr_t)admin_buf + 13);
            char resp[100];
            if (is_host_address(ntohl(request->int_ip), &int_if_info) == 0) {
                snprintf(resp, sizeof(resp), "PORT_FORWARD FAILED: Invalid internal IP %s\n", 
                    inet_ntoa(*(struct in_addr*)&request->int_ip));
            } else {
                struct nat_binding binding = nat_add_port_forward(
                    ntohl(request->int_ip), ntohs(request->int_port),
                    ntohl(ext_if_info.ip_addr.s_addr), ntohs(request->ext_port),
                    IPPROTO_TCP);
                if (binding.is_valid == 0) {
                    snprintf(resp, sizeof(resp), "PORT_FORWARD FAILED: Port invalid or already in use\n");
                } else {
                    snprintf(resp, sizeof(resp), "PORT_FORWARD OK: %s:%d -> %d\n",
                        inet_ntoa(*(struct in_addr*)&request->int_ip),
                        ntohs(request->int_port),
                        ntohs(request->ext_port));
                }
            }
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strncmp(admin_buf, "DEL_FORWARD ", 12) == 0) {
            port_forward_info *request = (port_forward_info*)((uintptr_t)admin_buf + 12);
            char resp[100];
            int r = nat_delete_port_forward(ntohl(request->int_ip), ntohs(request->int_port), 
                ntohl(ext_if_info.ip_addr.s_addr), ntohs(request->ext_port), 
                IPPROTO_TCP);
            if (r == 0) {
                snprintf(resp, sizeof(resp), "DEL_FORWARD OK: %s:%d -> %d\n",
                    inet_ntoa(*(struct in_addr*)&request->int_ip),
                    ntohs(request->int_port),
                    ntohs(request->ext_port));
            } else {
                snprintf(resp, sizeof(resp), "DEL_FORWARD FAILED: %s:%d -> %d\n",
                    inet_ntoa(*(struct in_addr*)&request->int_ip),
                    ntohs(request->int_port),
                    ntohs(request->ext_port));
            }
            sendto(admin_fd, resp, strlen(resp), 0,
                    (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strcmp(admin_buf, "PRINT_FORWARD") == 0) {
            memset(nat_table_str, 0, sizeof(nat_table_str));
            get_nat_table_string(nat_table_str, sizeof(nat_table_str), 1);
            if (sendto(admin_fd, nat_table_str, strlen(nat_table_str), 0,
                       (struct sockaddr *)&client_addr, client_addr_len) < 0) {
                perror("Admin thread: sendto failed");
            }
        }
        else if (strncmp(admin_buf, "LATENCY ", 8) == 0) {
            char netcidr[32] = {0};
            if (sscanf(admin_buf + 8, " %31s", netcidr) != 1) {
                const char *usage = "Usage: LATENCY <network/CIDR>\n";
                sendto(admin_fd, usage, strlen(usage), 0,
                       (struct sockaddr*)&client_addr, client_addr_len);
            } else {
                char latbuf[16384];
                memset(latbuf, 0, sizeof(latbuf));
                latency_probe_all(netcidr, latbuf, sizeof(latbuf));
                sendto(admin_fd, latbuf, strlen(latbuf), 0,
                       (struct sockaddr*)&client_addr, client_addr_len);
            }
        }
        else {
            const char *resp = "UNKNOWN COMMAND\n";
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
    }
    close(admin_fd);
    pthread_exit(NULL);
}

void extract_l4_fields(void *l4, uint8_t proto, uint16_t *src_port, uint16_t *dst_port, size_t *l4_hdr_len, bool *is_tcp_fin, bool *is_tcp_ack, bool *is_tcp_rst, bool include_extra_details) {
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        *src_port = ntohs(t->source);
        *dst_port = ntohs(t->dest);

        if (!include_extra_details) return;

        *l4_hdr_len = t->doff * 4;

        if (t->fin) *is_tcp_fin = true;
        if (t->ack) *is_tcp_ack = true;
        if (t->rst) *is_tcp_rst = true;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        *src_port = ntohs(u->source);
        *dst_port = ntohs(u->dest);

        if (!include_extra_details) return;

        *l4_hdr_len = sizeof(struct udphdr); 
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            *src_port = ntohs(icmp->un.echo.id);
            *dst_port = *src_port;

            if (!include_extra_details) return;

            *l4_hdr_len = sizeof(struct icmphdr);
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }
}

void handle_outbound_packet(unsigned char *buf, ssize_t n) {
    // filter for outbound TCP/UPD/ICMP packets
    struct ether_header *eth = (struct ether_header *)buf;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    struct ip *ip = (struct ip *)(buf + sizeof(*eth));
    if (checksum(ip, ip->ip_hl * 4) != 0) return;
    if (is_host_address(ntohl(ip->ip_src.s_addr), &int_if_info) == 0) return;
    // if (is_public_address(ntohl(ip->ip_dst.s_addr)) == 0) return;
    if (is_outbound_traffic(ntohl(ip->ip_dst.s_addr), &int_if_info) == 0) return;
    
    if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {} 
    else if (ip->ip_p == IPPROTO_ICMP) {                             // TODO: exclude hairpinning
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + ip->ip_hl * 4);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {}
        else return;
    } else {
        return;
    }

    // filter out abandoned traffic to certain dst_ip
    void *l4 = (unsigned char *)ip + ip->ip_hl * 4;
    size_t l4_total_len = ntohs(ip->ip_len) - ip->ip_hl * 4;
    if (filter_should_drop(ip->ip_p, l4, l4_total_len, ip->ip_src.s_addr))
        return;

    
    // extract session identifer (src_ip, src_port, dst_ip, dst_port, proto) in host byte order
    // also zero out the l4 header checksum
    uint32_t src_ip = ntohl(ip->ip_src.s_addr);
    uint32_t dst_ip = ntohl(ip->ip_dst.s_addr);
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = ip->ip_p;
    
    size_t l4_hdr_len = 0;
    bool is_tcp_fin = false;
    bool is_tcp_ack = false;
    bool is_tcp_rst = false;
    extract_l4_fields(l4, proto, &src_port, &dst_port, &l4_hdr_len, &is_tcp_fin, &is_tcp_ack, &is_tcp_rst, true);

    // Hairpin NAT: internal host -> external IP port‐forward hairpin
    struct nat_binding hp, e;
    hp.is_valid = false;
    e.is_valid = false;
    if (ip->ip_dst.s_addr == ext_if_info.ip_addr.s_addr) {
        if (proto == IPPROTO_ICMP) return; // ignore ICMP to gateway
        else {
            e = nat_lookup_outbound(src_ip, src_port, dst_ip, dst_port, proto, is_tcp_fin, is_tcp_ack, is_tcp_rst);
            hp = nat_lookup_inbound(e.ext_ip, e.ext_port, dst_ip, dst_port, proto, is_tcp_fin, is_tcp_ack, is_tcp_rst);
            if (!hp.is_valid) return; // ignore UDP/TCP to gateway without port-forward
        }
    }

    // detect start of session -- if so, create a new binding; otherwise, use the existing binding
    // time used for the binding is updated in nat_lookup_or_create_outbound
    if (!e.is_valid) e = nat_lookup_or_create_outbound(src_ip, src_port, dst_ip, dst_port, 
        proto, ntohl(ext_if_info.ip_addr.s_addr), is_tcp_fin, is_tcp_ack, is_tcp_rst);
    assert(e.is_valid);
    // printf("Found entry for outbound translation:\n");
    // print_nat_entry(e, 0);


    // make a copy of the original ip packet
    struct ip *ip_copy = malloc(ntohs(ip->ip_len));
    if (!ip_copy) return;
    memcpy(ip_copy, ip, ntohs(ip->ip_len));

    

    // translation:
    // TCP/UDP: src_ip -> ext_ip, src_port -> ext_port
    // ICMP: src_ip -> ext_ip, id -> ext_port
    // update checksum as well
    ip->ip_src.s_addr = htonl(e.ext_ip);
    ip->ip_sum = 0;
    ip->ip_sum = checksum(ip, ip->ip_hl * 4);
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        t->source = htons(e.ext_port);
        t->check = 0;
        t->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        u->source = htons(e.ext_port);
        u->check = 0;
        u->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            icmp->un.echo.id = htons(e.ext_port);
            icmp->checksum = 0;
            icmp->checksum = checksum(l4, l4_total_len);
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }

    // Hairpin NAT: internal host -> external IP port‐forward hairpin
    if (hp.is_valid) {
        ip->ip_dst.s_addr = htonl(hp.int_ip);
        ip->ip_sum = 0;
        ip->ip_sum = checksum(ip, ip->ip_hl * 4);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *t2 = l4;
            t2->dest = htons(hp.int_port);
            t2->check = 0;
            t2->check = l4_checksum(ip, l4, l4_total_len);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *u2 = l4;
            u2->dest = htons(hp.int_port);
            u2->check = 0;
            u2->check = l4_checksum(ip, l4, l4_total_len);
        } else {
            assert(0 && "Unreachable");
        }

        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_addr  = ip->ip_dst,
        };
        // send back on internal interface
        ssize_t ret = sendto(inward_sock, 
                            (void*)ip,
                            ntohs(ip->ip_len),
                            0,
                            (struct sockaddr*)&dst,
                            sizeof(dst));
        if (ret < 0) {
            perror("hairpinning");
            // print_tcpdump_packet(ip, ext_if_info.name);
        }
    } else {
        // retransmission; fragments or report frag needed if necessary
        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_addr  = ip->ip_dst,
        };
        ssize_t ret = sendto(outward_sock,
                            (void*)ip,
                            ntohs(ip->ip_len),
                            0,
                            (struct sockaddr*)&dst,
                            sizeof(dst));
        
        if (ret < 0 && ip->ip_p != IPPROTO_ICMP) {      // don't send error message for ICMP
            if (errno == EMSGSIZE) {
                int mtu = ext_if_info.mtu;
                if (ntohs(ip->ip_off) & IP_DF) {
                    send_icmp_frag_needed(inward_sock, ip_copy, int_if_info.ip_addr, mtu);
                } else {
                    fragment_and_send(outward_sock, ip, dst, mtu);
                }
            } else {
                perror("raw sendto");
                print_tcpdump_packet(ip, ext_if_info.name);
            }
        }
    }
    
    free(ip_copy);
}

void* outbound_worker(void *arg) {
    while (running) {
        pthread_mutex_lock(&outbound_queue.mutex);
        while (!outbound_queue.head && running) {
            pthread_cond_wait(&outbound_queue.cond, &outbound_queue.mutex);
        }
        if (!running) {
            pthread_mutex_unlock(&outbound_queue.mutex);
            break;
        }
        job_t *job = outbound_queue.head;
        outbound_queue.head = job->next;
        if (!outbound_queue.head) outbound_queue.tail = NULL;
        pthread_mutex_unlock(&outbound_queue.mutex);

        handle_outbound_packet(job->data, job->len);
        free(job->data);
        free(job);
    }
    return NULL;
}


void* thread_func_outbound(void *arg) {
    int raw_int = create_raw(int_if_info.name);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(raw_int, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char buf[BUF_SZ];
    while (running) {
        ssize_t n = recv(raw_int, buf, BUF_SZ, 0);
        if (n <= 0) continue;
        // enqueue job instead of spawning thread
        unsigned char *pkt_copy = malloc(n);
        if (!pkt_copy) continue;
        memcpy(pkt_copy, buf, n);

        job_t *job = malloc(sizeof(job_t));
        if (!job) {
            free(pkt_copy);
            continue;
        }
        job->data = pkt_copy;
        job->len = n;
        job->next = NULL;

        pthread_mutex_lock(&outbound_queue.mutex);
        if (outbound_queue.tail) outbound_queue.tail->next = job;
        else outbound_queue.head = job;
        outbound_queue.tail = job;
        pthread_cond_signal(&outbound_queue.cond);
        pthread_mutex_unlock(&outbound_queue.mutex);
    }
    
    close(raw_int);
    return NULL;
}

void handle_inbound_packet(unsigned char *buf, ssize_t n) {
    // filter for inbound TCP/UPD/ICMP packets
    struct ether_header *eth = (struct ether_header *)buf;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    struct ip *ip = (struct ip *)(buf + sizeof(*eth));
    struct ip *inner_ip = ip;                             // for ICMP error message
    if (checksum(ip, ip->ip_hl * 4) != 0) return;
    // if (is_public_address(ntohl(ip->ip_src.s_addr)) == 0) return;
    if (ip->ip_dst.s_addr != ext_if_info.ip_addr.s_addr) return;
    
    if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {} 
    else if (ip->ip_p == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + ip->ip_hl * 4);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            // existing echo handling
        } else {
            // ICMP error message handling: translate embedded original packet
            char *inner_buf = (char *)icmp + sizeof(*icmp);
            inner_ip = (struct ip *)inner_buf;
            if (inner_ip->ip_p == IPPROTO_ICMP) return;
        }
    } else {
        return;
    }
    
    void *l4 = (unsigned char *)inner_ip + inner_ip->ip_hl * 4;
    size_t l4_total_len = ntohs(inner_ip->ip_len) - inner_ip->ip_hl * 4;


    // extract session identifer (src_ip, src_port, dst_ip, dst_port, proto) in host byte order
    uint32_t src_ip = ntohl(inner_ip->ip_src.s_addr);
    uint32_t dst_ip = ntohl(inner_ip->ip_dst.s_addr);
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = inner_ip->ip_p;

    // extra details about the l4 header
    size_t l4_hdr_len = 0;
    bool is_tcp_fin = false;
    bool is_tcp_ack = false;
    bool is_tcp_rst = false;
    
    // printf("is icmp error: %d\n", inner_ip != ip);
    // printf("inner_ip %s %s -> %s\n", proto_name(inner_ip->ip_p), inet_ntoa(inner_ip->ip_src), inet_ntoa(inner_ip->ip_dst));
    // printf("outer_ip %s %s -> %s\n", proto_name(ip->ip_p), inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

    if (inner_ip == ip)
        extract_l4_fields(l4, proto, &src_port, &dst_port, &l4_hdr_len, &is_tcp_fin, &is_tcp_ack, &is_tcp_rst, true);
    else
        extract_l4_fields(l4, proto, &src_port, &dst_port, &l4_hdr_len, &is_tcp_fin, &is_tcp_ack, &is_tcp_rst, false);
    

    // find an existing binding
    // time used for the binding is updated in nat_lookup_or_create_outbound
    struct nat_binding e;
    if (inner_ip == ip)
        e = nat_lookup_inbound(src_ip, src_port, dst_ip, dst_port, proto, is_tcp_fin, is_tcp_ack, is_tcp_rst);
    else
        e = nat_lookup_inbound(dst_ip, dst_port, src_ip, src_port, proto, is_tcp_fin, is_tcp_ack, is_tcp_rst);
    if (!e.is_valid) return;
    // printf("Found entry for inbound translation:\n");
    // print_nat_entry(e, 0);


    // make a copy of the original ip packet
    struct ip *ip_copy = malloc(ntohs(ip->ip_len));
    if (!ip_copy) return;
    memcpy(ip_copy, ip, ntohs(ip->ip_len));
    


    // translation:
    // TCP/UDP: dst_ip -> int_ip, dst_port -> int_port
    // ICMP: dst_ip -> int_ip, id -> int_port
    // update checksum as well
    ip->ip_dst.s_addr = htonl(e.int_ip);
    ip->ip_sum = 0;
    ip->ip_sum = checksum(ip, ip->ip_hl * 4);
    if (inner_ip == ip) {
        if (proto == IPPROTO_TCP) {
            struct tcphdr *t = l4;
            t->dest = htons(e.int_port);
            t->check = 0;
            t->check = l4_checksum(ip, l4, l4_total_len);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *u = l4;
            u->dest = htons(e.int_port);
            u->check = 0;
            u->check = l4_checksum(ip, l4, l4_total_len);
        } else if (proto == IPPROTO_ICMP) {
            struct icmphdr *icmp = l4;
            if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
                icmp->un.echo.id = htons(e.int_port);
                icmp->checksum = 0;
                icmp->checksum = checksum(l4, l4_total_len);
            } else {
                assert(0 && "Unreachable");
            }
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(ip->ip_p == IPPROTO_ICMP);
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + ip->ip_hl * 4);
        assert(icmp->type != ICMP_ECHO && icmp->type != ICMP_ECHOREPLY);
        
        // replace source ip address, and source port of inner_ip
        inner_ip->ip_src.s_addr = htonl(e.int_ip);
        inner_ip->ip_sum = 0;
        inner_ip->ip_sum = checksum(inner_ip, inner_ip->ip_hl * 4);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *t = l4;
            t->source = htons(e.int_port);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *u = l4;
            u->source = htons(e.int_port);
        } else {
            assert(0 && "Unreachable");
        }

        // recalc outer ICMP checksum
        icmp->checksum = 0;
        icmp->checksum = checksum(icmp, ntohs(ip->ip_len) - ip->ip_hl * 4);
    }


    // retransmission; fragments or report frag needed if necessary
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_addr  = ip->ip_dst,
    };
    ssize_t ret = sendto(inward_sock,
                         (void*)ip,
                         ntohs(ip->ip_len),
                         0,
                         (struct sockaddr*)&dst,
                         sizeof(dst));
    if (ret < 0 && ip->ip_p != IPPROTO_ICMP) {      // don't send error message for ICMP
        if (errno == EMSGSIZE) {
            int mtu = int_if_info.mtu;
            if (ntohs(ip->ip_off) & IP_DF) {
                send_icmp_frag_needed(outward_sock, ip_copy, ext_if_info.ip_addr, mtu);
            } else {
                fragment_and_send(inward_sock, ip, dst, mtu);
            }
        } else {
            perror("raw sendto");
            print_tcpdump_packet(ip, int_if_info.name);
        }
    }
    free(ip_copy);
}

void* inbound_worker(void *arg) {
    while (running) {
        pthread_mutex_lock(&inbound_queue.mutex);
        while (!inbound_queue.head && running) {
            pthread_cond_wait(&inbound_queue.cond, &inbound_queue.mutex);
        }
        if (!running) {
            pthread_mutex_unlock(&inbound_queue.mutex);
            break;
        }
        job_t *job = inbound_queue.head;
        inbound_queue.head = job->next;
        if (!inbound_queue.head) inbound_queue.tail = NULL;
        pthread_mutex_unlock(&inbound_queue.mutex);

        handle_inbound_packet(job->data, job->len);
        free(job->data);
        free(job);
    }
    return NULL;
}

void* thread_func_inbound(void *arg) {
    int raw_ext = create_raw(ext_if_info.name);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(raw_ext, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char buf[BUF_SZ];
    while (running) {
        ssize_t n = recv(raw_ext, buf, BUF_SZ, 0);
        if (n <= 0) continue;
        // enqueue job instead of spawning thread
        unsigned char *pkt_copy = malloc(n);
        if (!pkt_copy) continue;
        memcpy(pkt_copy, buf, n);

        job_t *job = malloc(sizeof(job_t));
        if (!job) {
            free(pkt_copy);
            continue;
        }
        job->data = pkt_copy;
        job->len = n;
        job->next = NULL;

        pthread_mutex_lock(&inbound_queue.mutex);
        if (inbound_queue.tail) inbound_queue.tail->next = job;
        else inbound_queue.head = job;
        inbound_queue.tail = job;
        pthread_cond_signal(&inbound_queue.cond);
        pthread_mutex_unlock(&inbound_queue.mutex);
    }

    close(raw_ext);
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

#ifdef USE_EBPF
    if (unlink("/sys/fs/bpf/nat_map") != 0 && errno != ENOENT) {
        perror("cleanup: unlink nat_map");
    }
    if (link_out) {
        bpf_link__destroy(link_out);
        link_out = NULL;
    }
    if (link_in) {
        bpf_link__destroy(link_in);
        link_in = NULL;
    }
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
#endif
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <int_if> <ext_if>\n", argv[0]);
        return 1;
    }
    filter_init();

    // Initialize outbound queue and workers
    outbound_queue.head = outbound_queue.tail = NULL;
    pthread_mutex_init(&outbound_queue.mutex, NULL);
    pthread_cond_init(&outbound_queue.cond, NULL);
    for (int i = 0; i < NUM_WORKERS; ++i) {
        pthread_t t;
        pthread_create(&t, NULL, outbound_worker, NULL);
    }

    // Initialize inbound queue and workers
    inbound_queue.head = inbound_queue.tail = NULL;
    pthread_mutex_init(&inbound_queue.mutex, NULL);
    pthread_cond_init(&inbound_queue.cond, NULL);
    for (int i = 0; i < NUM_WORKERS; ++i) {
        pthread_t t;
        pthread_create(&t, NULL, inbound_worker, NULL);
    }

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
        printf("Internal MTU: %d\n", int_if_info.mtu);
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
        printf("External MTU: %d\n", ext_if_info.mtu);
    }

    outward_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    {
        if (outward_sock < 0) { perror("socket"); exit(1); }
        int on = 1;
        if (setsockopt(outward_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt IP_HDRINCL");
            exit(1);
        }
        if (setsockopt(outward_sock, SOL_SOCKET, SO_BINDTODEVICE,
            ext_if_info.name, strlen(ext_if_info.name)) < 0) {
            perror("bind to device");
        }
    }

    inward_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    {
        if (inward_sock < 0) { perror("socket"); exit(1); }
        int on = 1;
        if (setsockopt(inward_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt IP_HDRINCL");
            exit(1);
        }
        if (setsockopt(inward_sock, SOL_SOCKET, SO_BINDTODEVICE,
            int_if_info.name, strlen(int_if_info.name)) < 0) {
            perror("bind to device");
        }
    }

    pthread_t internal_thread, external_thread, gc_thread, admin_thread;

#ifdef USE_EBPF
    if (table_init("nat_kern.o", argv[1], argv[2])) {
        fprintf(stderr, "ERROR: failed to load BPF nat_kern.o\n");
        return 1;
    }
    unlink("/sys/fs/bpf/nat_map");
    if (bpf_obj_pin(nat_map_fd, "/sys/fs/bpf/nat_map") != 0) {
        perror("bpf_obj_pin_map");
        return -1;
    }
    // now attach each XDP program by section name:
    struct bpf_program *p_out = bpf_object__find_program_by_name(bpf_obj, "xdp_nat_out");
    struct bpf_program *p_in  = bpf_object__find_program_by_name(bpf_obj, "xdp_nat_in");
    int if_int = if_nametoindex(argv[1]); // eth1
    int if_ext = if_nametoindex(argv[2]); // eth0
    link_out = bpf_program__attach_xdp(p_out, if_int);
    if (!link_out) { perror("attach out"); exit(1); }
    link_in  = bpf_program__attach_xdp(p_in,  if_ext);
    if (!link_in)  { perror("attach in");  exit(1); }

    // Populate config map
    {
        // Find cfg_map file descriptor
        int cfg_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "cfg_map");
        if (cfg_map_fd < 0) {
            fprintf(stderr, "Error finding cfg_map fd\n");
            exit(EXIT_FAILURE);
        }
        // Prepare config based on interface info
        struct config_t {
            __u32 lan_ip;
            __u32 lan_mask;
            __u32 lan_broadcast;
            __u32 lan_mtu;
            __u32 public_ip;
            __u32 wan_mtu;
        } cfg = {
            .lan_ip = ntohl(int_if_info.ip_addr.s_addr),
            .lan_mask = ntohl(int_if_info.netmask.s_addr),
            .lan_broadcast = ntohl(int_if_info.broadcast.s_addr),
            .lan_mtu = int_if_info.mtu,
            .public_ip = ntohl(ext_if_info.ip_addr.s_addr),
            .wan_mtu = ext_if_info.mtu
        };
        __u32 key = 0;
        if (bpf_map_update_elem(cfg_map_fd, &key, &cfg, BPF_ANY) != 0) {
            perror("bpf_map_update_elem cfg_map");
            exit(EXIT_FAILURE);
        }
    }
#endif

    if (pthread_create(&admin_thread, NULL, admin_thread_func, NULL) != 0) {
        perror("Failed to create admin thread");
        exit(EXIT_FAILURE);
    }
    printf("Admin thread spawned.\n");


    if (pthread_create(&internal_thread, NULL, thread_func_outbound, NULL) != 0) {
        perror("Failed to create internal thread");
        exit(EXIT_FAILURE);
    }
    printf("Outward translation thread spawned.\n");

    if (pthread_create(&external_thread, NULL, thread_func_inbound, NULL) != 0) {
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

    puts("\n[+] NAT stopped.");

    return 0;
}


