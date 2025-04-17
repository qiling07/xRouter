#include "dhcp_packet.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

const uint8_t magic_cookie[4] = {99, 130, 83, 99};

uint16_t check_magic_cookie(uint8_t *options)
{
    for (int i = 0; i < MAGIC_COOKIE_SIZE; i++)
    {
        if (options[i] != magic_cookie[i])
        {
            return 0;
        }
    }
    return 1;
}

struct option_list parse_options(uint8_t *options, uint16_t len)
{
    struct option_list op_list;
    op_list.size = (len - MAGIC_COOKIE_SIZE) / 3;
    op_list.header = (struct option_tlv*)malloc(sizeof(struct option_tlv) * op_list.size);
    int n = 0;
    for (int i = MAGIC_COOKIE_SIZE; i < len; )
    {
        uint8_t c = options[i];
        if (c == OC_END) break;
        if (c == OC_PAD) 
        {
            ++i;
            continue;
        }

        op_list.header[n].code = c;
        if (++i >= len)
        {
            perror("An error occurs when parsing options of a DHCP packet\n");
            exit(-1);
        }
        c = options[i];
        op_list.header[n].len = c;
        if (i + c >= len)
        {
            perror("An error occurs when parsing options of a DHCP packet\n");
            exit(-1);
        }
        op_list.header[n].value = malloc((size_t)c);
        memcpy(op_list.header[n].value, &options[++i], c);
        ++n;
        i += c;
    }
    op_list.len = n;
    return op_list;
}

void release_option_list(struct option_list *list)
{
    for (int i = 0; i < list->len; i++)
    {
        free(list->header[i].value);
    }
    free(list->header);
}

uint16_t get_message_type(struct option_list *ops)
{
    for (int i = 0; i < ops->len; ++i)
    {
        if (ops->header[i].code == OC_MESSAGE_TYPE)
        {
            if (ops->header[i].len != 1)
            {
                perror("An error occurs when extracting the message type of a DHCP packet\n");
                exit(-1);
            }
            return ops->header[i].value[0];
        }
    }
    return MTC_INVALID;
}

struct option_tlv* get_option_tlv(struct option_list *ops, enum option_code op_code)
{
    for (int i = 0; i < ops->len; ++i)
    {
        if (ops->header[i].code == op_code)
        {
            return &(ops->header[i]);
        }
    }
    return NULL;
}

void print_dhcp_header(struct dhcp_packet *packet)
{
    char buf[2048];
    memset(buf, 0, sizeof(buf));
    size_t offset = 0;
    // op
    switch (packet->op)
    {
    case OP_BOOTREQUEST:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "op = OP_BOOTREQUEST\n");
        break;
    case OP_BOOTREPLY:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "op = OP_BOOTREPLY\n");
        break;
    default:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "Invalid op value: %u\n", packet->op);
        break;
    }
    // htype
    switch (packet->htype)
    {
    case HT_ETHERNET:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "htype = HT_ETHERNET\n");
        break;
    case HT_IEEE:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "htype = HT_IEEE\n");
        break;
    default:
    offset += snprintf(buf + offset, sizeof(buf) - offset, "Unknown htype value: %u\n", packet->htype);
        break;
    }
    // hlen
    offset += snprintf(buf + offset, sizeof(buf) - offset, "hlen = %u\n", packet->hlen);
    // hops
    offset += snprintf(buf + offset, sizeof(buf) - offset, "hops = %u\n", packet->hops);
    // xid
    offset += snprintf(buf + offset, sizeof(buf) - offset, "xid = %u\n", packet->xid);
    // secs
    offset += snprintf(buf + offset, sizeof(buf) - offset, "secs = %u\n", packet->secs);
    // flags
    switch (packet->flags)
    {
    case F_UNICAST:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "flags = F_UNICAST\n");
        break;
    case F_BROADCAST:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "flags = F_BROADCAST\n");
        break;
    default:
        offset += snprintf(buf + offset, sizeof(buf) - offset, "Unknown flags value: %u\n", packet->flags);
        break;
    }
    // ciaddr
    struct in_addr addr;
    char ip_str[INET_ADDRSTRLEN];
    addr.s_addr = packet->ciaddr;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    offset += snprintf(buf + offset, sizeof(buf) - offset, "ciaddr = %s\n", ip_str);
    // yiaddr
    addr.s_addr = packet->yiaddr;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    offset += snprintf(buf + offset, sizeof(buf) - offset, "yiaddr = %s\n", ip_str);
    // siaddr
    addr.s_addr = packet->siaddr;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    offset += snprintf(buf + offset, sizeof(buf) - offset, "siaddr = %s\n", ip_str);
    // giaddr
    addr.s_addr = packet->giaddr;
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    offset += snprintf(buf + offset, sizeof(buf) - offset, "giaddr = %s\n", ip_str);
    // chaddr
    offset += snprintf(buf + offset, sizeof(buf) - offset, "chaddr = ");
    for (int i = 0; i < packet->hlen; ++i)
    {
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%02x", packet->chaddr[i]);
        if (i < packet->hlen -1)
        {
            offset += snprintf(buf + offset, sizeof(buf) - offset, ":");   
        }
    }
    offset += snprintf(buf + offset, sizeof(buf) - offset, "\n");
    printf("%s", buf);
}


void print_dhcp_options(struct option_list *list)
{
    for (int i = 0; i < list->len; i++)
    {
        printf("code = %u\n", list->header[i].code);
        if (list->header[i].code == OC_MESSAGE_TYPE)
        {
            printf("message type code = %u\n", list->header[i].value[0]);
        }       
    }
}