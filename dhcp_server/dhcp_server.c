#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <net/if.h>
#include <linux/if.h>
#include "dhcp_server.h"
#include "dhcp_packet.h"

void process_dhcp_discover(struct dhcp_server *server, struct dhcp_packet *packet, struct option_list *options, struct dhcp_packet *reply, size_t *len){
    reply->op = (uint8_t)OP_BOOTREPLY;
    reply->htype = (uint8_t)HT_ETHERNET;
    reply->hlen = (uint8_t)MAC_ADDR_LENGTH;
    reply->hops = 0;
    reply->xid = packet->xid;
    // secs is filled by client
    reply->flags = packet->flags;
    // ciaddr is filled by client
    struct binding *offer_binding = offer_ip(server->pool, packet->chaddr);
    uint32_t ip = offer_binding->ip;
    reply->yiaddr = htonl(ip);
    // ignore `siaddr`
    reply->giaddr = packet->giaddr;
    memcpy(reply->chaddr, packet->chaddr, MAC_ADDR_LENGTH);
    // ignore `sname` & `file`
    memcpy(reply->options, magic_cookie, MAGIC_COOKIE_SIZE);
    // set `OC_MESSAGE_TYPE`
    uint32_t options_ofst = MAGIC_COOKIE_SIZE;
    reply->options[options_ofst++] = (uint8_t)OC_MESSAGE_TYPE;
    reply->options[options_ofst++] = 1;
    reply->options[options_ofst++] = (uint8_t)MTC_DHCPOFFER;
    // set `OC_SERVER_ID`
    reply->options[options_ofst++] = (uint8_t)OC_SERVER_ID;
    reply->options[options_ofst++] = 4;
    inet_pton(AF_INET, server->conf.ip_addr, &(reply->options[options_ofst]));
    options_ofst += 4;

    // set lease time
    reply->options[options_ofst++] = OC_LEASE_TIME;
    reply->options[options_ofst++] = 4;
    pthread_mutex_lock(&(server->pool->manage.mlt_lock));
    struct mac_lease_time *mlt = get_mac_lease_time(server->pool, packet->chaddr);\
    pthread_mutex_unlock(&(server->pool->manage.mlt_lock));
    uint32_t lease_time_nbo;
    if (mlt)
        lease_time_nbo = htonl(mlt->lease_time);
    else
        lease_time_nbo = htonl(server->conf.lease_time);
    memcpy(&reply->options[options_ofst], &lease_time_nbo, 4);
    options_ofst += 4;

    // set renew time
    reply->options[options_ofst++] = OC_RENEWAL_TIME;
    reply->options[options_ofst++] = 4;
    uint32_t renew_time_nbo;
    if (mlt)
        renew_time_nbo = htonl(mlt->lease_time/2);
    else
        renew_time_nbo = htonl(server->conf.renew_time);
    memcpy(&reply->options[options_ofst], &renew_time_nbo, 4);
    options_ofst += 4;

    // set rebind time
    reply->options[options_ofst++] = OC_REBINDING_TIME;
    reply->options[options_ofst++] = 4;
    uint32_t rebind_time_nbo;
    if (mlt)
    rebind_time_nbo = htonl(mlt->lease_time * 4 / 5);
    else
    rebind_time_nbo = htonl(server->conf.rebinding_time);
    memcpy(&reply->options[options_ofst], &rebind_time_nbo, 4);
    options_ofst += 4;

    // set parameters according to the parameter request list
    struct option_tlv *parameters_tlv = get_option_tlv(options, OC_PARAMETER_LIST);
    for (int i = 0; i < parameters_tlv->len; ++i)
    {
        // reply->options[options_ofst++] = parameters_tlv->value[i];
        printf("option %d\n", parameters_tlv->value[i]);
        switch (parameters_tlv->value[i])
        {
        case OC_SUBNET_MASK:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.netmask, &(reply->options[options_ofst]));
            options_ofst += 4;
            break;
        case OC_BROADCAST_ADDR:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.broadcast, &(reply->options[options_ofst]));
            options_ofst += 4;
            break;
        case OC_ROUTER:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.gateway, &(reply->options[options_ofst]));
            options_ofst += 4;
            break;
        case OC_DOMAIN_NAME:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = strlen(server->conf.domain_name);
            memcpy(&reply->options[options_ofst], server->conf.domain_name, strlen(server->conf.domain_name));
            options_ofst += strlen(server->conf.domain_name);
            break;
        case OC_DNS:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.dns_ip, &(reply->options[options_ofst]));
            options_ofst += 4;
            break;
        case OC_REBINDING_TIME:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            memcpy(&reply->options[options_ofst], &server->conf.rebinding_time, 4);
            options_ofst += 4;
            break;
        default:
            break;
        }
    }
    reply->options[options_ofst++] = OC_END;
    // send reply
    *len = DHCP_HEADER_SIZE + options_ofst;
}

void process_dhcp_request(struct dhcp_server *server, struct dhcp_packet *packet, struct option_list *options, struct dhcp_packet *reply, size_t *len, uint8_t *send_packet){
    // check wether the server is selected
    struct option_tlv* server_id_tlv = get_option_tlv(options, OC_SERVER_ID);
    uint32_t ip_no = ip_str_to_network_order(server->conf.ip_addr);
    
    // `server_id_tlv == NULL` indicates this packet is unicast to the server (renew) or broadcast to the server in the rebinding phase
    if (server_id_tlv == NULL || server_id_tlv != NULL && memcmp(&ip_no, server_id_tlv->value, 4) == 0)
    {
        // is selected
        // commit the binding
        if (packet->hlen == MAC_ADDR_LENGTH)
        {
            reply->op = (uint8_t)OP_BOOTREPLY;
            reply->htype = (uint8_t)HT_ETHERNET;
            reply->hlen = (uint8_t)MAC_ADDR_LENGTH;
            reply->hops = 0;
            reply->xid = packet->xid;
            // secs is filled by client
            reply->flags = packet->flags;
            reply->giaddr = packet->giaddr;
            memcpy(reply->chaddr, packet->chaddr, MAC_ADDR_LENGTH);
            // ignore `sname` & `file`
            memcpy(reply->options, magic_cookie, MAGIC_COOKIE_SIZE);
            // set `OC_MESSAGE_TYPE`
            uint32_t options_ofst = MAGIC_COOKIE_SIZE;
            reply->options[options_ofst++] = (uint8_t)OC_MESSAGE_TYPE;
            reply->options[options_ofst++] = 1;

            uint32_t request_ip; // network order
            struct binding *b;
            // for renewal & rebinding
            if (server_id_tlv == NULL)
            {
                // renew request do not have OC_REQUESTED_IP
                // In a renew/rebinding request, the request_ip is the ciaddr
                request_ip = packet->ciaddr;
                b = try_renew(server->pool, ntohl(packet->ciaddr), packet->chaddr, server->conf.lease_time);
                if (b)
                {
                    struct in_addr addr;
                    char ip_str[INET_ADDRSTRLEN];
                    addr.s_addr = packet->ciaddr;
                    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
                    printf("Successfully renew ip %s\n", ip_str);
                }
            }
            // for initialization & rebindimh
            else
            {
                // get option 50 (OC_REQUESTED_IP)
                struct option_tlv* requesr_ip_tlv = get_option_tlv(options, OC_REQUESTED_IP);
                memcpy(&request_ip, requesr_ip_tlv->value, 4);
                b = allocate_ip(server->pool, ntohl(request_ip), packet->chaddr, server->conf.lease_time);
            }

            if (b == NULL)
            {
                // send NAK
                printf("send NAK\n");
                *send_packet = 1;
                reply->options[options_ofst++] = (uint8_t)MTC_DHCPNAK;
            }
            else {
                // send ACK
                printf("send ACK\n");
                *send_packet = 1;
                reply->yiaddr = request_ip;
                reply->options[options_ofst++] = (uint8_t)MTC_DHCPACK;
            }

            // set `OC_SERVER_ID`
            reply->options[options_ofst++] = (uint8_t)OC_SERVER_ID;
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.ip_addr, &(reply->options[options_ofst]));
            options_ofst += 4;

            // set lease time
            reply->options[options_ofst++] = OC_LEASE_TIME;
            reply->options[options_ofst++] = 4;
            pthread_mutex_lock(&(server->pool->manage.mlt_lock));
            struct mac_lease_time *mlt = get_mac_lease_time(server->pool, packet->chaddr);
            pthread_mutex_unlock(&(server->pool->manage.mlt_lock));
            uint32_t lease_time_nbo;
            if (mlt)
                lease_time_nbo = htonl(mlt->lease_time);
            else
                lease_time_nbo = htonl(server->conf.lease_time);
            memcpy(&reply->options[options_ofst], &lease_time_nbo, 4);
            options_ofst += 4;

            // set renew time
            reply->options[options_ofst++] = OC_RENEWAL_TIME;
            reply->options[options_ofst++] = 4;
            uint32_t renew_time_nbo;
            if (mlt)
                renew_time_nbo = htonl(mlt->lease_time/2);
            else
                renew_time_nbo = htonl(server->conf.renew_time);
            memcpy(&reply->options[options_ofst], &renew_time_nbo, 4);
            options_ofst += 4;

            // set rebind time
            reply->options[options_ofst++] = OC_REBINDING_TIME;
            reply->options[options_ofst++] = 4;
            uint32_t rebind_time_nbo;
            if (mlt)
            rebind_time_nbo = htonl(mlt->lease_time * 4 / 5);
            else
            rebind_time_nbo = htonl(server->conf.rebinding_time);
            memcpy(&reply->options[options_ofst], &rebind_time_nbo, 4);
            options_ofst += 4;
                    
            // TODO: refactor code
            struct option_tlv *parameters_tlv = get_option_tlv(options, OC_PARAMETER_LIST);
            for (int i = 0; i < parameters_tlv->len; ++i)
            {
                // reply->options[options_ofst++] = parameters_tlv->value[i];
                printf("option %d\n", parameters_tlv->value[i]);
                switch (parameters_tlv->value[i])
                {
                case OC_SUBNET_MASK:
                    reply->options[options_ofst++] = parameters_tlv->value[i];
                    reply->options[options_ofst++] = 4;
                    inet_pton(AF_INET, server->conf.netmask, &(reply->options[options_ofst]));
                    options_ofst += 4;
                    break;
                case OC_BROADCAST_ADDR:
                    reply->options[options_ofst++] = parameters_tlv->value[i];
                    reply->options[options_ofst++] = 4;
                    inet_pton(AF_INET, server->conf.broadcast, &(reply->options[options_ofst]));
                    options_ofst += 4;
                    break;
                case OC_ROUTER:
                    reply->options[options_ofst++] = parameters_tlv->value[i];
                    reply->options[options_ofst++] = 4;
                    inet_pton(AF_INET, server->conf.gateway, &(reply->options[options_ofst]));
                    options_ofst += 4;
                    break;
                case OC_DOMAIN_NAME:
                    reply->options[options_ofst++] = parameters_tlv->value[i];
                    reply->options[options_ofst++] = strlen(server->conf.domain_name);
                    memcpy(&reply->options[options_ofst], server->conf.domain_name, strlen(server->conf.domain_name));
                    options_ofst += strlen(server->conf.domain_name);
                    break;
                case OC_DNS:
                    reply->options[options_ofst++] = parameters_tlv->value[i];
                    reply->options[options_ofst++] = 4;
                    inet_pton(AF_INET, server->conf.dns_ip, &(reply->options[options_ofst]));
                    options_ofst += 4;
                    break;
                default:
                    break;
                }
            }
            reply->options[options_ofst++] = OC_END;
            // send reply
            *len = DHCP_HEADER_SIZE + options_ofst;
        }
        else{
            perror("unsupported chaddr type\n");
            exit(-1);
        }
    }
    else{
        printf("not selected\n");
        // is not selected
        if (packet->hlen == MAC_ADDR_LENGTH)
        {
            cancel_offer(server->pool, packet->chaddr);
            *send_packet = 0;
        }
        else{
            perror("unsupported chaddr type\n");
            exit(-1);
        }
    }
    
}

void process_dhcp_decline(){
    printf("Haven't implemented yet\n");
}

void process_dhcp_release(struct dhcp_server *server, uint32_t client_ip, struct dhcp_packet *packet, struct option_list *options){
    // verify OC_SERVER_ID
    struct option_tlv *server_id_tlv = get_option_tlv(options, OC_SERVER_ID);
    uint32_t server_id_no;
    memcpy(&server_id_no, server_id_tlv->value, server_id_tlv->len);
    uint32_t ip_no = ip_str_to_network_order(server->conf.ip_addr);
    if (server_id_no != ip_no)
    {
        printf("OC_SERVER_ID does not match with the server ip\n");
        return;
    }
    // verify client_ip and ciaddr
    uint32_t ciaddr_ho = ntohl(packet->ciaddr);
    if (ciaddr_ho != client_ip)
    {
        printf("invalid ciaddr in the DHCP_RELEASE packet\n");
        return;
    }
    struct binding* released_b = release_ip(server->pool, ciaddr_ho, packet->chaddr);
    if (released_b == NULL)
    {
        printf("No matched lease in the leasing pool\n");
        return;
    }
    printf("Successfully released the lease\n");
}

void process_dhcp_inform(){
    printf("Haven't implemented yet\n");
}

// Receive command from the admin (similar)
void *admin_thread_func(void *arg) {
    struct dhcp_server *server = (struct dhcp_server *)arg;

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
    admin_addr.sin_port = htons(9998);

    if (bind(admin_fd, (struct sockaddr *)&admin_addr, sizeof(admin_addr)) < 0) {
        perror("Admin thread: bind failed");
        close(admin_fd);
        pthread_exit(NULL);
    }

    printf("Admin thread: listening on port 9998...\n");
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(admin_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        client_addr_len = sizeof(client_addr);
        int n = recvfrom(admin_fd, admin_buf, sizeof(admin_buf) - 1, 0,
                           (struct sockaddr *)&client_addr, &client_addr_len);
        if (n < 0) {
            // perror("Admin thread: recvfrom failed");
            continue;
        }
        printf("Admin thread: received command: %s\n", admin_buf);
        if (strncmp(admin_buf, "SET_LEASE_TIME ", 15) == 0)
        {
            uint8_t mac[MAC_ADDR_LENGTH];
            uint32_t lease_time;

            const char *params_p = admin_buf + 15;
            
            if (sscanf(params_p, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %u", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5], &lease_time) == 7)
            {
                pthread_mutex_lock(&(server->pool->manage.mlt_lock));
                uint8_t suc = set_ip_lease_time(server->pool, mac, lease_time);
                pthread_mutex_unlock(&(server->pool->manage.mlt_lock));
                if (!suc)
                {
                    fprintf(stderr, "set lease time failed.\n");
                    const char *usage = "set lease time failed.\n";
                    sendto(admin_fd, usage, strlen(usage), 0,
                        (struct sockaddr*)&client_addr, client_addr_len);
                }
                else
                {
                    fprintf(stderr, "Successfully set lease time: %02x:%02x:%02x:%02x:%02x:%02x: %u.\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], lease_time);
                    char usage[512];
                    snprintf(usage, sizeof(usage), "Successfully set lease time: %02x:%02x:%02x:%02x:%02x:%02x: %u.\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], lease_time);
                    sendto(admin_fd, usage, strlen(usage), 0,
                        (struct sockaddr*)&client_addr, client_addr_len);
                }
            }
            else
            {
                fprintf(stderr, "Invalid SET_LEASE_TIME format.\n");
                const char *usage = "Invalid SET_LEASE_TIME format.\n";
                sendto(admin_fd, usage, strlen(usage), 0,
                    (struct sockaddr*)&client_addr, client_addr_len);
            }
        }
        else if (strncmp(admin_buf, "RESERVE_IP ", 10) == 0)
        {
            uint8_t mac[MAC_ADDR_LENGTH];
            char ip_str[INET_ADDRSTRLEN];
            uint32_t ip_ho;

            const char *params_p = admin_buf + 10;
            
            if (sscanf(params_p, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %s", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5], ip_str) == 7)
            {
                ip_ho = ip_str_to_host_order(ip_str);
                pthread_mutex_lock(&(server->pool->manage.reservations_lock));
                uint8_t suc = set_reservation(server->pool, mac, ip_ho);
                pthread_mutex_unlock(&(server->pool->manage.reservations_lock));
                if (!suc)
                {
                    fprintf(stderr, "reserve ip failed.\n");
                    const char *usage = "reserve ip failed.\n";
                    sendto(admin_fd, usage, strlen(usage), 0,
                        (struct sockaddr*)&client_addr, client_addr_len);
                }
                else
                {
                    fprintf(stderr, "Successfully reserve ip: %02x:%02x:%02x:%02x:%02x:%02x %s.\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_str);
                    char usage[512];
                    snprintf(usage, sizeof(usage), "Successfully reserve ip: %02x:%02x:%02x:%02x:%02x:%02x %s.\n",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_str);
                    sendto(admin_fd, usage, strlen(usage), 0,
                        (struct sockaddr*)&client_addr, client_addr_len);
                }
            }
            else
            {
                fprintf(stderr, "Invalid RESERVE_IP format.\n");
                const char *usage = "Invalid RESERVE_IP format.\n";
                sendto(admin_fd, usage, strlen(usage), 0,
                    (struct sockaddr*)&client_addr, client_addr_len);
            }
        }
        else {
            const char *resp = "UNKNOWN COMMAND\n";
            sendto(admin_fd, resp, strlen(resp), 0,
                (struct sockaddr*)&client_addr, client_addr_len);
        }
    }
    // close(admin_fd);
    // pthread_exit(NULL);
}

int main(int argc, char *argv[]){
    // Create a UDP Socket to receive DHCP requests
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // configure UDP Server socket address
    struct sockaddr_in addr_s;
    addr_s.sin_port = htons(DHCP_S_PORT);
    addr_s.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_s.sin_family = AF_INET;

    // bind socket
    if (bind(sock, (struct sockaddr *)&addr_s, sizeof(addr_s)) < 0)
    {
        perror("An error occurs when binding the socket.\n");
        close(sock);
        exit(-1);
    }

    struct dhcp_server *server = init_dhcp_server(sock);
    
    // set `SO_BROADCAST` to receive DHCP Discover messages
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
    {
        perror("An error occurs when setting SO_BROADCAST.\n");
        close(sock);
        exit(-1);
    }

    // bind to the LAN interface
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, server->conf.lan_interface, strlen(server->conf.lan_interface)))
    {
        perror("An error occurs when setting SO_BINDTODEVICE.\n");
        close(sock);
        exit(-1);
    }
    
    char buf[DHCP_BUF_SIZE];
    struct sockaddr_in addr_c;
    socklen_t addr_len;
    int request_len;

    // configure broadcast socket
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(68);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    // Create a thread to communicate with the manager client
    pthread_t admin_thread;
    if (pthread_create(&admin_thread, NULL, admin_thread_func, (void *)server) != 0) {
        perror("An error occurs when creating the manager thread\n");
        exit(-1);
    }

    while (1)
    {
        addr_len = sizeof(addr_c);
        request_len = recvfrom(sock, buf, DHCP_BUF_SIZE, 0, (struct sockaddr *)&addr_c, &addr_len);
        if (request_len < 0)
        {
            perror("An error occurs when receiving a DHCP packet\n");
            exit(-1);
        }
        printf("Receive a packet on %s, request_len = %d\n", server->conf.lan_interface, request_len);

        // parse and dispatch the received packet
        struct dhcp_packet *packet = buf;
        print_dhcp_header(packet);
        if (packet->op == OP_BOOTREQUEST)
        {
            struct option_list op_list = parse_options(packet->options, request_len - DHCP_HEADER_SIZE);
            print_dhcp_options(&op_list);
            uint16_t message_type = get_message_type(&op_list);

            struct dhcp_packet reply_packet;
            memset(&reply_packet, 0, sizeof(struct dhcp_packet));
            size_t reply_len = -1;

            switch (message_type)
            {
            case MTC_INVALID:
                perror("Invalid DHCP message type\n");
                exit(-1);
                break;
            case MTC_DHCPDISCOVER:
                process_dhcp_discover(server, packet, &op_list, &reply_packet, &reply_len);
                if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0)
                {
                    perror("An error occurs when sending a DHCPOFFER packet\n");
                    exit(-1);
                }
                printf("Send a packet:\n");
                print_dhcp_header(&reply_packet);
                break;
            case MTC_DHCPREQUEST:
                {
                    uint8_t send = 0;
                    process_dhcp_request(server, packet, &op_list, &reply_packet, &reply_len, &send);
                    if (send == 0) break;
                    // check `flag`
                    if (packet->flags == F_UNICAST)
                    {
                        if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0)
                        {
                            perror("An error occurs when sending a DHCPACK/DHCPNAK packet\n");
                            exit(-1);
                        }
                    }
                    else {
                        if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&addr_c, sizeof(addr_c)) < 0)
                        {
                            perror("An error occurs when sending a DHCPACK/DHCPNAK packet\n");
                            exit(-1);
                        }
                    }
                    printf("Send a packet:\n");
                    print_dhcp_header(&reply_packet);
                    break;
                }
            case MTC_DHCPDECLINE:
                process_dhcp_decline();
                break;
            case MTC_DHCPRELEASE: {
                uint32_t client_ip = ntohl(addr_c.sin_addr.s_addr);
                process_dhcp_release(server, client_ip, packet, &op_list);
                break;
		}
            case MTC_DHCPINFORM:
                process_dhcp_inform();
                break;
            default:
                perror("Invalid DHCP message type\n");
                exit(-1);
                break;
            }
            // release option list
            release_option_list(&op_list);
        }
    }
    release_dhcp_server(server);
}
