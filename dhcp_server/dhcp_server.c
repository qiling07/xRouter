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
    inet_pton(AF_INET, server->conf.ip, &(reply->options[options_ofst]));
    options_ofst += 4;
    // set parameters according to the parameter request list
    struct option_tlv *parameters_tlv = get_option_tlv(options, OC_PARAMETER_LIST);
    for (int i = 0; i < parameters_tlv->len; ++i)
    {
        // reply->options[options_ofst++] = parameters_tlv->value[i];
        printf("option %d\n", parameters_tlv->value[i]);
        switch (parameters_tlv->value[i])
        {
        case OC_LEASE_TIME:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            memcpy(&reply->options[options_ofst], &server->conf.lease_time, 4);
            options_ofst += 4;
            break;
        case OC_RENEWAL_TIME:
            reply->options[options_ofst++] = parameters_tlv->value[i];
            reply->options[options_ofst++] = 4;
            memcpy(&reply->options[options_ofst], &server->conf.renew_time, 4);
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

void process_dhcp_request(struct dhcp_server *server, struct dhcp_packet *packet, struct option_list *options, struct dhcp_packet *reply, size_t *len){
    // check wether the server is selected
    uint8_t server_id[4];
    inet_pton(AF_INET, server->conf.ip, server_id);
    struct option_tlv* server_id_tlv = get_option_tlv(options, OC_SERVER_ID);
    if (memcmp(server_id, server_id_tlv->value, 4) == 0)
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
            // get option 50 (OC_REQUESTED_IP)
            struct option_tlv* requesr_ip_tlv = get_option_tlv(options, OC_REQUESTED_IP);
            uint32_t request_ip;
            memcpy(&request_ip, requesr_ip_tlv->value, 4);
            struct binding *b = allocate_ip(server->pool, ntohl(request_ip), packet->chaddr, server->conf.lease_time);
            if (b == NULL)
            {
                // send NAK
                printf("send NAK\n");
                reply->options[options_ofst++] = (uint8_t)MTC_DHCPNAK;
            }
            else {
                // send ACK
                printf("send ACK\n");
                reply->yiaddr = request_ip;
                reply->options[options_ofst++] = (uint8_t)MTC_DHCPACK;
            }
            // set `OC_SERVER_ID`
            reply->options[options_ofst++] = (uint8_t)OC_SERVER_ID;
            reply->options[options_ofst++] = 4;
            inet_pton(AF_INET, server->conf.ip, &(reply->options[options_ofst]));
            options_ofst += 4;
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
        // is not selected
        if (packet->hlen == MAC_ADDR_LENGTH)
        {
            cancel_offer(server->pool, packet->chaddr);
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

void process_dhcp_release(){
    printf("Haven't implemented yet\n");
}

void process_dhcp_inform(){
    printf("Haven't implemented yet\n");
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
                process_dhcp_request(server, packet, &op_list, &reply_packet, &reply_len);
                // TODO: Using broadcast or unicast should depend on the broadcast flag in the DUCP header and whether the client has obtained an IP address or not
                if (sendto(server->sock, &(reply_packet), reply_len, 0, (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0)
                {
                    perror("An error occurs when sending a DHCPACK/DHCPNAK packet\n");
                    exit(-1);
                }
                break;
            case MTC_DHCPDECLINE:
                process_dhcp_decline();
                break;
            case MTC_DHCPRELEASE:
                process_dhcp_release();
                break;
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