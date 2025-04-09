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
    uint32_t ip = offer_ip(server->pool, packet->chaddr);
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
    inet_pton(AF_INET, server->conf.ip, &(reply->options[options_ofst]));
    options_ofst += 4;
    // set parameters according to the parameter request list
    struct option_tlv *parameters_tlv = get_option_tlv(options, OC_PARAMETER_LIST);
    for (int i = 0; i < parameters_tlv->len; ++i)
    {
        reply->options[options_ofst++] = parameters_tlv->value[i];
        switch (parameters_tlv->value[i])
        {
        case OC_LEASE_TIME:
            reply->options[options_ofst++] = 4;
            ((uint32_t *)reply->options)[options_ofst] = server->conf.lease_time;
            options_ofst += 4;
            break;
        case OC_RENEWAL_TIME:
            reply->options[options_ofst++] = 4;
            ((uint32_t *)reply->options)[options_ofst] = server->conf.renew_time;
            options_ofst += 4;
            break;
        case OC_REBINDING_TIME:
            reply->options[options_ofst++] = 4;
            ((uint32_t *)reply->options)[options_ofst] = server->conf.rebinding_time;
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

void process_dhcp_request(){
    
}

void process_dhcp_decline(){
    
}

void process_dhcp_release(){
    
}

void process_dhcp_pinform(){
    
}




void* process_dhcp(void *arg){
    printf("DHCP Server start...\n");
    struct dhcp_server *server = (struct dhcp_server *)arg;
    ssize_t request_len;
    char buf[DHCP_BUF_SIZE];
    struct sockaddr_in addr_c;
    socklen_t addr_len;
    while (1)
    {
        // TODO: modify this sequential server to concurrent server
        addr_len = sizeof(addr_c);
        // FIXME: thread should be created after receiving a packet
        request_len = recvfrom(server->sock, buf, DHCP_BUF_SIZE, 0, (struct sockaddr *)&addr_c, &addr_len);
        if (request_len < 0)
        {
            perror("An error occurs when receiving a DHCP packet\n");
            exit(-1);
        }

        // parse and dispatch the received packet
        printf("process_dhcp 3\n");
        struct dhcp_packet *packet = buf;
        printf("process_dhcp 4\n");
        if (packet->op == OP_BOOTREQUEST)
        {
            printf("process_dhcp 5\n");
            struct option_list op_list = parse_options(packet->options, request_len - DHCP_HEADER_SIZE);
            uint16_t message_type = get_message_type(&op_list);
            struct dhcp_packet reply_packet;
            size_t reply_len = -1;
            switch (message_type)
            {
            case MTC_INVALID:
                perror("Invalid DHCP message type\n");
                exit(-1);
                break;
            case MTC_DHCPDISCOVER:
                process_dhcp_discover(server, packet, &op_list, &reply_packet, &reply_len);
                if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&addr_c, sizeof(addr_c)) < 0)
                {
                    perror("An error occurs when sending a DHCPOFFER packet\n");
                    exit(-1);
                }
                break;
            case MTC_DHCPREQUEST:
            case MTC_DHCPDECLINE:
            case MTC_DHCPRELEASE:
            case MTC_DHCPINFORM:
                printf("Haven't implemented yet\n");
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
    
    // Start a dhcp thread
    // pthread_t tid;
    // if (pthread_create(&tid, NULL, process_dhcp, server) != 0)
    // {
    //     perror("An error occurs when creating a `dhcp_process` thread.\n");
    //     close(sock);
    //     exit(-1);
    // }
    
    // pthread_join(tid, NULL);

    char buf[DHCP_BUF_SIZE];
    struct sockaddr_in addr_c;
    socklen_t addr_len;
    int request_len;
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
            uint16_t message_type = get_message_type(&op_list);
            struct dhcp_packet reply_packet;
            size_t reply_len = -1;
            switch (message_type)
            {
            case MTC_INVALID:
                perror("Invalid DHCP message type\n");
                exit(-1);
                break;
            case MTC_DHCPDISCOVER:
                process_dhcp_discover(server, packet, &op_list, &reply_packet, &reply_len);
                if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&addr_c, sizeof(addr_c)) < 0)
                {
                    perror("An error occurs when sending a DHCPOFFER packet\n");
                    exit(-1);
                }
                printf("Send a packet:\n");
                print_dhcp_header(&reply_packet);
                break;
            case MTC_DHCPREQUEST:
            case MTC_DHCPDECLINE:
            case MTC_DHCPRELEASE:
            case MTC_DHCPINFORM:
                printf("Haven't implemented yet\n");
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