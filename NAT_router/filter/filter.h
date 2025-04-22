// ---- filter.h ----
#ifndef FILTER_H
#define FILTER_H

#include <pthread.h>

#define DOMAIN_MAX_LEN 256
typedef struct filter_entry {
    char domain[DOMAIN_MAX_LEN];
    struct filter_entry *next;
} filter_entry_t;

void filter_init();
void filter_cleanup();

int  filter_add(const char *domain);
int  filter_del(const char *domain);
char *filter_list_str(char *buf, size_t buflen);

int  filter_check_http(const unsigned char *payload, size_t len);
int  filter_check_tls_sni(const unsigned char *payload, size_t len);

#endif // FILTER_H
