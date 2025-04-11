#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53

// DNS Header 
typedef struct {
    unsigned short id;       
    unsigned short flags;    
    unsigned short qdcount;  
    unsigned short ancount;  
    unsigned short nscount;  
    unsigned short arcount;  
} __attribute__((packed)) DNSHeader;

typedef struct {
    unsigned short qtype;    
    unsigned short qclass;   
} __attribute__((packed)) DNSQuestion;

typedef struct {
    unsigned short name;     
    unsigned short type;     
    unsigned short cls;    
    unsigned int ttl;        
    unsigned short rdlength; 
    // RDATA 紧跟在后面
} __attribute__((packed)) DNSAnswer;

// e.g. "google.com" to
//    [6] g o o g l e [3] c o m [0]
void encode_domain_name(unsigned char *dest, const char *src) {
    while (*src) {
        const char *dot = strchr(src, '.');
        int len;
        if (dot)
            len = dot - src;
        else
            len = strlen(src);
        *dest++ = (unsigned char)len;
        memcpy(dest, src, len);
        dest += len;
        if (!dot)
            break;
        src = dot + 1;
    }
    *dest++ = 0;  
}

// return the length of query packet
// buffer must be large enough
// hostname （e.g."google.com"）
void create_dns_query(unsigned char *buffer, const char *hostname, int *query_len) {
    DNSHeader *dns = (DNSHeader *)buffer;
    dns->id = htons(12345);         // random ID
    dns->flags = htons(0x0100);     
    dns->qdcount = htons(1);        
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    unsigned char *qname = buffer + sizeof(DNSHeader);
    encode_domain_name(qname, hostname);

    int qname_len = 0;
    unsigned char *p = qname;
    while (1) {
        qname_len++;
        if (*p == 0)
            break;
        p++;
    }

    DNSQuestion *question = (DNSQuestion *)(qname + qname_len);
    question->qtype = htons(1);   // query type A
    question->qclass = htons(1);  // class IN

    *query_len = sizeof(DNSHeader) + qname_len + sizeof(DNSQuestion);
}

void print_payload(const unsigned char *payload, int len) {
    for (int i = 0; i < len; i++) {
        if (isprint(payload[i]))
            printf("%c ", payload[i]);
        else
            printf("%02X ", payload[i]);
    }
    printf("\n");
}

void send_dns_query(const char *hostname) {
    int sockfd;
    struct sockaddr_in server_addr, local_addr;
    unsigned char buffer[512];
    int query_len;

    // UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(62800);         //
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, DNS_SERVER, &server_addr.sin_addr) <= 0) {
        perror("Invalid DNS server address");
        close(sockfd);
        exit(1);
    }


    create_dns_query(buffer, hostname, &query_len);

    printf("DNS Query Packet (%d bytes):\n", query_len);
    print_payload(buffer, query_len);


    if (sendto(sockfd, buffer, query_len, 0,
               (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(1);
    }
    printf("Query sent, waiting for response...\n");

    socklen_t addr_len = sizeof(server_addr);
    int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                            (struct sockaddr *)&server_addr, &addr_len);
    if (recv_len < 0) {
        perror("recvfrom failed");
        close(sockfd);
        exit(1);
    }
    printf("Received %d bytes\n", recv_len);

    DNSHeader *resp_header = (DNSHeader *)buffer;
    int answer_count = ntohs(resp_header->ancount);
    printf("Answer count: %d\n", answer_count);
    if (answer_count < 1) {
        printf("No answers in the response.\n");
        close(sockfd);
        return;
    }


    unsigned char *ptr = buffer + sizeof(DNSHeader);

    while(*ptr != 0)
        ptr++;
    ptr++;
    ptr += sizeof(DNSQuestion); 

    DNSAnswer *answer = (DNSAnswer *)ptr;
    if (ntohs(answer->type) == 1 && ntohs(answer->rdlength) == 4) { 
        struct in_addr resolved_ip;
        memcpy(&resolved_ip, ptr + sizeof(DNSAnswer), 4);
        printf("Resolved IP for %s: %s\n", hostname, inet_ntoa(resolved_ip));
    } else {
        printf("First answer is not a valid A record.\n");
    }

    close(sockfd);
}

int main() {
    const char *hostname = "google.com";
    send_dns_query(hostname);
    return 0;
}
