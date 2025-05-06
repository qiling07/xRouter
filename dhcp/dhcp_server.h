#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "addr_pool.h"

#define DHCP_S_PORT 67
#define DHCP_C_PORT 68
#define DHCP_BUF_SIZE 548
#define CONF_FILE_PATH "dhcp.conf"

struct dhcp_conf{
    char *ip_addr; // network byte order
    uint8_t hw_addr[6];
    char *isp_interface;
    char *lan_interface;
    char *gateway;
    char *netmask;
    char *broadcast;
    char *dns_ip;
    char *domain_name;
    // address pool
    char *start_ip;
    char *end_ip;
    uint32_t pool_size;
    uint32_t lease_time;
    uint32_t renew_time;
    uint32_t rebinding_time;
};

struct dhcp_server{
    int sock;
    struct dhcp_conf conf;
    struct addr_pool *pool;
};

struct dhcp_server* init_dhcp_server(int socket){
    struct dhcp_server* server = (struct dhcp_server*)malloc(sizeof(struct dhcp_server));
    memset(server, 0, sizeof(struct dhcp_server));
    server->sock = socket;
    parse_dhcp_conf(&server->conf);
    server->pool =  init_addr_pool(server->conf.start_ip, server->conf.end_ip, server->conf.pool_size);
    return server;
}

void release_dhcp_server(struct dhcp_server* server){
    // free configuration
    free(server->conf.isp_interface);
    free(server->conf.lan_interface);
    free(server->conf.gateway);
    free(server->conf.netmask);
    free(server->conf.broadcast);
    free(server->conf.dns_ip);
    free(server->conf.domain_name);
    free(server->conf.start_ip);
    free(server->conf.end_ip);
    
    release_addr_pool(server->pool);
    free(server);
}

int set_hwaddr(const char *ifname, struct dhcp_conf *conf) {
    // Open a socket for ioctl calls
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Get hardware (MAC) address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return -1;
    }
    memcpy(conf->hw_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);

    return 0;
}

void parse_dhcp_conf(struct dhcp_conf *conf) {
    FILE *fp = fopen(CONF_FILE_PATH, "r");
    if (!fp) {
        perror("fopen " CONF_FILE_PATH);
        exit(EXIT_FAILURE);
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char key[64], val[128];
        if (sscanf(line, " %63s %127s", key, val) != 2) {
            continue;
        }
        if (strcmp(key, "ISP_interface") == 0) {
            conf->isp_interface = strdup(val);
        } else if (strcmp(key, "LAN_interface") == 0) {
            conf->lan_interface = strdup(val);
        } else if (strcmp(key, "gateway") == 0) {
            conf->gateway = strdup(val);
        } else if (strcmp(key, "netmask") == 0) {
            conf->netmask = strdup(val);
        } else if (strcmp(key, "broadcast") == 0) {
            conf->broadcast = strdup(val);
        } else if (strcmp(key, "dns_ip") == 0) {
            conf->dns_ip = strdup(val);
        } else if (strcmp(key, "domain_name") == 0) {
            conf->domain_name = strdup(val);
        } else if (strcmp(key, "start_ip") == 0) {
            conf->start_ip = strdup(val);
        } else if (strcmp(key, "end_ip") == 0) {
            conf->end_ip = strdup(val);
        } else if (strcmp(key, "pool_size") == 0) {
            conf->pool_size = (uint32_t)atoi(val);
        } else if (strcmp(key, "lease_time") == 0) {
            conf->lease_time = (uint32_t)atoi(val);
        } else if (strcmp(key, "renew_time") == 0) {
            conf->renew_time = (uint32_t)atoi(val);
        } else if (strcmp(key, "rebinding_time") == 0) {
            conf->rebinding_time = (uint32_t)atoi(val);
        }
    }
    fclose(fp);

    /* Derive the server IP from gateway */
    conf->ip_addr = strdup(conf->gateway);

    /* Retrieve hardware (MAC) address of ISP interface */
    if (set_hwaddr(conf->isp_interface, conf) != 0) {
        fprintf(stderr, "Failed to get MAC for %s\n", conf->isp_interface);
        exit(EXIT_FAILURE);
    }
}

#endif
