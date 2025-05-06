// ---- filter.h ----
#ifndef FILTER_H
#define FILTER_H

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define DOMAIN_MAX_LEN 256
typedef struct filter_rule {
    char      domain[DOMAIN_MAX_LEN];
    uint32_t  ip;        // IP address in network byte order
    struct filter_rule *next;
} filter_rule_t;

void filter_init();
void filter_cleanup();

int  filter_add(const char *domain, const char *ip_str);
int  filter_del(const char *domain, const char *ip_str);
char *filter_list_str(char *buf, size_t buflen);

int  filter_check_http(const unsigned char *payload, size_t len);
int  filter_check_tls_sni(const unsigned char *payload, size_t len);

int  filter_should_drop(uint8_t proto,
    const void *l4, size_t l4len,
    uint32_t src_ip);


#endif // FILTER_H
