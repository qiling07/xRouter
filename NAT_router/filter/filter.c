// ---- filter.c ----
#include "filter.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static filter_entry_t *head = NULL;
static pthread_mutex_t  mtx  = PTHREAD_MUTEX_INITIALIZER;

void filter_init() {
    head = NULL;
}

void filter_cleanup() {
    pthread_mutex_lock(&mtx);
    filter_entry_t *cur = head, *tmp;
    while (cur) {
        tmp = cur->next;
        free(cur);
        cur = tmp;
    }
    head = NULL;
    pthread_mutex_unlock(&mtx);
}

int filter_add(const char *domain) {
    pthread_mutex_lock(&mtx);
    for (filter_entry_t *e = head; e; e = e->next)
        if (strcmp(e->domain, domain) == 0) {
            pthread_mutex_unlock(&mtx);
            return 1; // already exists
        }
    filter_entry_t *n = malloc(sizeof(*n));
    if (!n) { pthread_mutex_unlock(&mtx); return -1; }
    strncpy(n->domain, domain, DOMAIN_MAX_LEN-1);
    n->domain[DOMAIN_MAX_LEN-1] = '\0';
    n->next = head;
    head = n;
    pthread_mutex_unlock(&mtx);
    return 0;
}

int filter_del(const char *domain) {
    pthread_mutex_lock(&mtx);
    filter_entry_t **pp = &head;
    while (*pp) {
        if (strcmp((*pp)->domain, domain) == 0) {
            filter_entry_t *tofree = *pp;
            *pp = tofree->next;
            free(tofree);
            pthread_mutex_unlock(&mtx);
            return 0;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&mtx);
    return 1; // not found
}

char *filter_list_str(char *buf, size_t buflen) {
    pthread_mutex_lock(&mtx);
    size_t off = 0;
    for (filter_entry_t *e = head; e; e = e->next) {
        int ret = snprintf(buf+off, buflen-off, "%s\n", e->domain);
        if (ret < 0 || (size_t)ret >= buflen-off) break;
        off += ret;
    }
    pthread_mutex_unlock(&mtx);
    return buf;
}

// HTTP Host Header
int filter_check_http(const unsigned char *p, size_t len) {
    const char *host_hdr = "Host:";
    for (size_t i = 0; i + strlen(host_hdr) < len; ++i) {
        if (memcmp(p+i, host_hdr, strlen(host_hdr))==0) {
            // i+5 
            const char *start = (const char*)p + i + strlen(host_hdr);
            while (*start==' '&& (size_t)(start-(const char*)p) < len) start++;
            size_t end = 0;
            while (start[end] && start[end] != '\r' && start[end] != ':' 
                   && (i + end) < len) end++;
            char domain[DOMAIN_MAX_LEN] = {0};
            memcpy(domain, start, end < DOMAIN_MAX_LEN-1 ? end : DOMAIN_MAX_LEN-1);
            pthread_mutex_lock(&mtx);
            for (filter_entry_t *e = head; e; e = e->next) {
                if (strstr(domain, e->domain)) {
                    pthread_mutex_unlock(&mtx);
                    return 1;
                }
            }
            pthread_mutex_unlock(&mtx);
            return 0;
        }
    }
    return 0;
}

// filter_check_tls_sni()