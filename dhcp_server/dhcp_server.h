#ifndef DHCP_SERVER_H
#define DHCP_SERVER_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "addr_pool.h"

#define DHCP_S_PORT 67
#define DHCP_C_PORT 68
#define DHCP_BUF_SIZE 548
#define CONF_FILE_PATH "dhcp.conf"

struct dhcp_conf{
    char *ip;
    char *mac;
    char *isp_interface;
    char *lan_interface;
    char *gateway;
    char *netmask;
    char *broadcast;
    char *dns_ip;
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
    free(server->conf.ip);
    free(server->conf.mac);
    free(server->conf.isp_interface);
    free(server->conf.lan_interface);
    free(server->conf.gateway);
    free(server->conf.netmask);
    free(server->conf.broadcast);
    free(server->conf.dns_ip);
    free(server->conf.start_ip);
    free(server->conf.end_ip);
    
    release_addr_pool(server->pool);
    free(server);
}

void parse_dhcp_conf(struct dhcp_conf *conf){
    // TODO: read parameters from the configuration file or pass parameters via command-line flags
    conf->ip = strdup("10.0.2.15");
    conf->mac = strdup("08:00:27:9a:fa:f2");
    conf->isp_interface = strdup("enp0s3");
    conf->lan_interface = strdup("enp0s8");
    conf->gateway = strdup("192.168.20.1");
    conf->netmask = strdup("255.255.255.0");
    conf->broadcast = strdup("192.168.20.255");
    conf->dns_ip = strdup("8.8.8.8");
    conf->start_ip = strdup("192.168.20.101");
    conf->end_ip = strdup("192.168.10.200");
    conf->pool_size = 100;
    conf->lease_time = 600;
    conf->renew_time = 300;
    conf->rebinding_time = 525;
}

#endif
