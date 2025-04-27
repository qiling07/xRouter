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
#include "filter/filter.h"
#include "latency.h"
#include <net/if.h>
#include <sys/ioctl.h>


volatile sig_atomic_t running = 1;
interface_info int_if_info, ext_if_info;
int outward_sock = -1;
int inward_sock = -1;

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
            char *domain = admin_buf + 11;
            int r = filter_add(domain);
            const char *resp = (r == 0)
                ? "ADD_FILTER OK\n"
                : "ADD_FILTER FAILED\n";
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
        else if (strncmp(admin_buf, "DEL_FILTER ", 11) == 0) {
            char *domain = admin_buf + 11;
            int r = filter_del(domain);
            const char *resp = (r == 0)
                ? "DEL_FILTER OK\n"
                : "DEL_FILTER FAILED\n";
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
            struct nat_entry *e = NULL;
            char resp[100];
            if (is_host_address(ntohl(request->int_ip), &int_if_info) == 0) {
                snprintf(resp, sizeof(resp), "PORT_FORWARD FAILED: Invalid internal IP %s\n", 
                    inet_ntoa(*(struct in_addr*)&request->int_ip));
            } else if (NULL == nat_add_port_forward(
                ntohl(request->int_ip), ntohs(request->int_port),
                ntohl(ext_if_info.ip_addr.s_addr), ntohs(request->ext_port),
                IPPROTO_TCP)) {
                snprintf(resp, sizeof(resp), "PORT_FORWARD FAILED: Port invalid or already in use\n");
            } else {
                snprintf(resp, sizeof(resp), "PORT_FORWARD OK: %s:%d -> %d\n",
                    inet_ntoa(*(struct in_addr*)&request->int_ip),
                    ntohs(request->int_port),
                    ntohs(request->ext_port));
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


void handle_outbound_packet(unsigned char *buf, ssize_t n) {
    // filter for outbound TCP/UPD/ICMP packets
    struct ether_header *eth = (struct ether_header *)buf;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    struct ip *ip = (struct ip *)(buf + sizeof(*eth));
    if (checksum(ip, ip->ip_hl * 4) != 0) return;
    if (is_host_address(ntohl(ip->ip_src.s_addr), &int_if_info) == 0) return;
    if (is_public_address(ntohl(ip->ip_dst.s_addr)) == 0) return;
    
    if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {} 
    else if (ip->ip_p == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + ip->ip_hl * 4);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {}
        else return;
    } else {
        return;
    }

    // filter out abandoned traffic to certain dst_ip
    void *l4 = (unsigned char *)ip + ip->ip_hl * 4;
    size_t l4_total_len = ntohs(ip->ip_len) - ip->ip_hl * 4;
    if (filter_should_drop(ip->ip_p, l4, l4_total_len))
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

    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        src_port = ntohs(t->source);
        dst_port = ntohs(t->dest);

        l4_hdr_len = t->doff * 4;
        t->check = 0;

        // if (t->fin) is_tcp_fin = true;
        // if (t->ack) is_tcp_ack = true;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        src_port = ntohs(u->source);
        dst_port = ntohs(u->dest);

        l4_hdr_len = sizeof(struct udphdr); 
        u->check = 0;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            src_port = ntohs(icmp->un.echo.id);
            dst_port = src_port;

            l4_hdr_len = sizeof(struct icmphdr);
            icmp->checksum = 0;
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }
    
    // detect start of session -- if so, create a new binding; otherwise, use the existing binding
    // time used for the binding is updated in nat_lookup_or_create_outbound
    struct nat_entry *e = nat_lookup_or_create_outbound(src_ip, src_port, dst_ip, dst_port, proto, ntohl(ext_if_info.ip_addr.s_addr));
    assert(e != NULL);
    
    // if ((e->int_fin==1)&&(e->ext_fin==1)&&(is_tcp_ack)&&(!is_tcp_fin)){
    //     e->last_ack = 1;
    // }
    // if (is_tcp_fin) {        
    //     e->int_fin = 1;
    // }


    // translation:
    // TCP/UDP: src_ip -> ext_ip, src_port -> ext_port
    // ICMP: src_ip -> ext_ip, id -> ext_port
    // update checksum as well
    ip->ip_src.s_addr = htonl(e->ext_ip);
    ip->ip_sum = 0;
    ip->ip_sum = checksum(ip, ip->ip_hl * 4);
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        t->source = htons(e->ext_port);
        t->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        u->source = htons(e->ext_port);
        u->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            icmp->un.echo.id = htons(e->ext_port);
            icmp->checksum = checksum(l4, l4_total_len);
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }

    // TODO: check rst for TCP

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
    
    if (ret < 0) {
        if (errno == EMSGSIZE) {
            int mtu = ext_if_info.mtu;
            if (ip->ip_off & htons(IP_DF)) {
                send_icmp_frag_needed(outward_sock, ip, dst, mtu);
            } else {
                fragment_and_send(outward_sock, ip, dst, mtu);
            }
        } else {
            perror("raw sendto");
            print_tcpdump_packet(ip, ext_if_info.name);
        }
    }
    // if (is_tcp_ack) {
    //     nat_lookup_and_remove(ip->ip_src.s_addr, src_port, ip->ip_p, 0);
    // }
}
struct packet_data {
    unsigned char *data;
    ssize_t len;
};
void* packet_worker_func_outbound(void *arg) {
    struct packet_data *pkt = arg;
    handle_outbound_packet(pkt->data, pkt->len);
    free(pkt->data);
    free(pkt);
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

        unsigned char *pkt_copy = malloc(n);
        if (!pkt_copy) continue;
        memcpy(pkt_copy, buf, n);

        pthread_t worker;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        struct packet_data *p = malloc(sizeof(struct packet_data));
        if (!p) {
            free(pkt_copy);
            continue;
        }
        p->data = pkt_copy;
        p->len = n;
        if (pthread_create(&worker, &attr, packet_worker_func_outbound, p) != 0) {
            free(pkt_copy);
            free(p);
        }
        pthread_attr_destroy(&attr);
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
    if (checksum(ip, ip->ip_hl * 4) != 0) return;
    if (is_public_address(ntohl(ip->ip_src.s_addr)) == 0) return;
    if (ip->ip_dst.s_addr != ext_if_info.ip_addr.s_addr) return;
    
    if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP) {} 
    else if (ip->ip_p == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(*eth) + ip->ip_hl * 4);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {}
        else return;
    } else {
        return;
    }
    
    void *l4 = (unsigned char *)ip + ip->ip_hl * 4;
    size_t l4_total_len = ntohs(ip->ip_len) - ip->ip_hl * 4;

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

    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        src_port = ntohs(t->source);
        dst_port = ntohs(t->dest);

        l4_hdr_len = t->doff * 4;
        t->check = 0;

        // if (t->fin) is_tcp_fin = true;
        // if (t->ack) is_tcp_ack = true;
        // if (t->rst) is_tcp_rst = true;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        src_port = ntohs(u->source);
        dst_port = ntohs(u->dest);

        l4_hdr_len = sizeof(struct udphdr); 
        u->check = 0;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            src_port = ntohs(icmp->un.echo.id);
            dst_port = src_port;

            l4_hdr_len = sizeof(struct icmphdr);
            icmp->checksum = 0;
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }
    
    // find an existing binding
    // time used for the binding is updated in nat_lookup_or_create_outbound
    struct nat_entry *e = nat_lookup_inbound(src_ip, src_port, dst_ip, dst_port, proto);
    if (!e) return;

    // update TCP connections status
    // if ((e->int_fin==1)&&(e->ext_fin==1)&&(is_tcp_ack)&&(!is_tcp_fin)){
    //     e->last_ack = 1;
    // }
    // if (is_tcp_fin) {
    //     e->ext_fin = 1;
    // }
    // if (is_tcp_rst){
    //     e->ext_fin = 1;
    //     e->last_ack = 1;
    //     e->int_fin = 1;
    //     //printf("connection rst!\n");
    // }

    // translation:
    // TCP/UDP: dst_ip -> int_ip, dst_port -> int_port
    // ICMP: dst_ip -> int_ip, id -> int_port
    // update checksum as well
    ip->ip_dst.s_addr = htonl(e->int_ip);
    ip->ip_sum = 0;
    ip->ip_sum = checksum(ip, ip->ip_hl * 4);
    if (proto == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        t->dest = htons(e->int_port);
        t->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *u = l4;
        u->dest = htons(e->int_port);
        u->check = l4_checksum(ip, l4, l4_total_len);
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4;
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            icmp->un.echo.id = htons(e->int_port);
            icmp->checksum = checksum(l4, l4_total_len);
        } else {
            assert(0 && "Unreachable");
        }
    } else {
        assert(0 && "Unreachable");
    }

    // TODO check rst for TCP

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
    // if ((is_tcp_ack)||(is_tcp_rst)){
    //     nat_lookup_and_remove(ip->ip_dst.s_addr, id_or_port, ip->ip_p, 1);
    // }
    if (ret < 0) {
        if (errno == EMSGSIZE) {
            int mtu = int_if_info.mtu;
            if (ip->ip_off & htons(IP_DF)) {
                send_icmp_frag_needed(inward_sock, ip, dst, mtu);
            } else {
                fragment_and_send(inward_sock, ip, dst, mtu);
            }
        } else {
            perror("raw sendto");
            print_tcpdump_packet(ip, int_if_info.name);
        }
    }

}

void* packet_worker_func_inbound(void *arg) {
    struct packet_data *pkt = arg;
    handle_inbound_packet(pkt->data, pkt->len);
    free(pkt->data);
    free(pkt);
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

        unsigned char *pkt_copy = malloc(n);
        if (!pkt_copy) continue;
        memcpy(pkt_copy, buf, n);

        pthread_t worker;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        struct packet_data *p = malloc(sizeof(struct packet_data));
        if (!p) {
            free(pkt_copy);
            continue;
        }
        p->data = pkt_copy;
        p->len = n;
        if (pthread_create(&worker, &attr, packet_worker_func_inbound, p) != 0) {
            free(pkt_copy);
            free(p);
        }
        pthread_attr_destroy(&attr);
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
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <int_if> <ext_if>\n", argv[0]);
        return 1;
    }
    filter_init();

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


