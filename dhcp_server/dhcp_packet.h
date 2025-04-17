#include <stdlib.h>
#include <stdint.h>
#ifndef DHCP_PACKET_H
#define DHCP_PACKET_H

// Format of a DHCP message (ref: https://datatracker.ietf.org/doc/html/rfc2131)
// 
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
// +---------------+---------------+---------------+---------------+
// |                            xid (4)                            |
// +-------------------------------+-------------------------------+
// |           secs (2)            |           flags (2)           |
// +-------------------------------+-------------------------------+
// |                          ciaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          yiaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          siaddr  (4)                          |
// +---------------------------------------------------------------+
// |                          giaddr  (4)                          |
// +---------------------------------------------------------------+
// |                                                               |
// |                          chaddr  (16)                         |
// |                                                               |
// |                                                               |
// +---------------------------------------------------------------+
// |                                                               |
// |                          sname   (64)                         |
// +---------------------------------------------------------------+
// |                                                               |
// |                          file    (128)                        |
// +---------------------------------------------------------------+
// |                                                               |
// |                          options (variable)                   |
// +---------------------------------------------------------------+

enum op_code{
    OP_BOOTREQUEST = 1,
    OP_BOOTREPLY = 2
};

enum htype_code{
    HT_ETHERNET = 1,
    HT_IEEE = 6
};

#define MAC_ADDR_LENGTH 6

enum flag_code{
    F_UNICAST = 0,
    F_BROADCAST = 0x8000
};

#define DHCP_HEADER_SIZE 236
struct dhcp_packet
{
    uint8_t op;     // Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t htype;  // Hardware address type
    uint8_t hlen;   // Hardware address length
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;    // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state and can respond to ARP requests.
    uint32_t yiaddr;    // 'your' (client) IP address.
    uint32_t siaddr;    // IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    uint32_t giaddr;    // Relay agent IP address, used in booting via a relay agent.
    uint8_t chaddr[16]; // Client hardware address
    uint8_t sname[64];  // Optional server host name, null terminated string.
    uint8_t file[128];
    // --------------- The above is the header of the packet -----------------
    uint8_t options[312];   // Optional parameters field. The 'options' field is now variable length. 
                            // A DHCP client must be prepared to receive DHCP messages with an 'options' field of at least length 312 octets.
};

// options: The complete set of options is defined in RFC 1533
enum option_code{
    // RFC 1497 Vendor Extensions
    OC_PAD = 0,
    OC_END = 255,
    OC_SUBNET_MASK = 1,
    OC_ROUTER = 3,
    OC_DNS = 6,
    // DHCP Extensions
    OC_REQUESTED_IP = 50,
    OC_LEASE_TIME = 51,
    OC_OPTION_OVERLOAD = 52,
    OC_MESSAGE_TYPE = 53,
    OC_SERVER_ID = 54,
    OC_PARAMETER_LIST = 55,
    OC_MESSAGE = 56,
    OC_MAX_MESSAGE_SIZE = 57,
    OC_RENEWAL_TIME = 58,
    OC_REBINDING_TIME = 59,
    oC_CLIENT_ID = 61
    // TODO: Option 1, 28, 3, 15, 6
    // TODO: Option 61 (client identifier)
};

// each option in the `options` field is encoded in the Type-Length-Value (TLV) format

struct option_tlv
{
    uint8_t code;
    uint8_t len;
    uint8_t *value;
};

struct option_list
{
    unsigned int size;
    unsigned int len;
    struct option_tlv *header;  // `count` of `option_tlv`s are allocated at `header`
};

// The first four octets of the 'options' field of the DHCP message contain the (decimal) values 99, 130, 83 and 99, respectively 
// (this is the same magic cookie as is defined in RFC 1497 [17])
#define MAGIC_COOKIE_SIZE 4
extern const uint8_t magic_cookie[4];
uint16_t check_magic_cookie(uint8_t *options);
struct option_list parse_options(uint8_t *options, uint16_t len);
void release_option_list(struct option_list *list);
void print_dhcp_header(struct dhcp_packet *packet);
void print_dhcp_options(struct option_list *list);

// One particular option - the "DHCP message type" option - must be included in every DHCP message.  
// This option defines the "type" of the DHCP message. 
enum message_type_code
{
    MTC_INVALID = 0,
    MTC_DHCPDISCOVER = 1,   // Client broadcast to locate available servers.
    MTC_DHCPOFFER = 2,  // Server to client in response to DHCPDISCOVER with offer of configuration parameters.
    MTC_DHCPREQUEST = 3,    // Client message to servers either 
                            // (a) requesting offered parameters from one server and implicitly declining offers from all others, 
                            // (b) confirming correctness of previously allocated address after, e.g., system reboot, 
                            // or (c) extending the lease on a particular network address.
    MTC_DHCPDECLINE = 4,    // Client to server indicating network address is already in use.
    MTC_DHCPACK = 5,    // Server to client with configuration parameters, including committed network address.
    MTC_DHCPNAK = 6,    // Server to client indicating client's notion of network address is incorrect (e.g., client has moved to new subnet) or client's lease as expired
    MTC_DHCPRELEASE = 7,    // Client to server relinquishing network address and cancelling remaining lease.
    MTC_DHCPINFORM = 8  // Client to server, asking only for local configuration parameters; client already has externally configured network address.
};

uint16_t get_message_type(struct option_list *ops);
struct option_tlv* get_option_tlv(struct option_list *ops, enum option_code);


#endif