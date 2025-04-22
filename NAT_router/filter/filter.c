/**
 * filter.c
 *
 * Implements domain-based packet filtering for DNS, HTTP, and (stub) TLS-SNI.
 * Provides a linked-list blacklist of domains and a single entry point
 * filter_should_drop() to decide whether to drop a given L4 packet.
 */

 #include "filter.h"

 #include <string.h>
 #include <stdlib.h>
 #include <stdio.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <netinet/udp.h>
 #include <netinet/ip_icmp.h>
 #include <pthread.h>
 
 static filter_entry_t *head = NULL;
 static pthread_mutex_t  mtx  = PTHREAD_MUTEX_INITIALIZER;
 
 void filter_init(void) {
     pthread_mutex_lock(&mtx);
     head = NULL;
     pthread_mutex_unlock(&mtx);
 }
 
 void filter_cleanup(void) {
     pthread_mutex_lock(&mtx);
     filter_entry_t *cur = head;
     while (cur) {
         filter_entry_t *tmp = cur->next;
         free(cur);
         cur = tmp;
     }
     head = NULL;
     pthread_mutex_unlock(&mtx);
 }
 
 int filter_add(const char *domain) {
     pthread_mutex_lock(&mtx);
     for (filter_entry_t *e = head; e; e = e->next) {
         if (strcmp(e->domain, domain) == 0) {
             pthread_mutex_unlock(&mtx);
             return 1;  // already exists
         }
     }
     filter_entry_t *node = malloc(sizeof(*node));
     if (!node) {
         pthread_mutex_unlock(&mtx);
         return -1;  // allocation failed
     }
     strncpy(node->domain, domain, DOMAIN_MAX_LEN - 1);
     node->domain[DOMAIN_MAX_LEN - 1] = '\0';
     node->next = head;
     head = node;
     pthread_mutex_unlock(&mtx);
     return 0;
 }
 
 int filter_del(const char *domain) {
     pthread_mutex_lock(&mtx);
     filter_entry_t **pp = &head;
     while (*pp) {
         filter_entry_t *e = *pp;
         if (strcmp(e->domain, domain) == 0) {
             *pp = e->next;
             free(e);
             pthread_mutex_unlock(&mtx);
             return 0;  // removed
         }
         pp = &e->next;
     }
     pthread_mutex_unlock(&mtx);
     return 1;  // not found
 }
 
 char *filter_list_str(char *buf, size_t buflen) {
     pthread_mutex_lock(&mtx);
     size_t off = 0;
     for (filter_entry_t *e = head; e; e = e->next) {
         int n = snprintf(buf + off, buflen - off, "%s\n", e->domain);
         if (n < 0 || (size_t)n >= buflen - off) break;
         off += n;
     }
     if (off < buflen) buf[off] = '\0';
     pthread_mutex_unlock(&mtx);
     return buf;
 }
 
 /**
  * Inspect DNS query payload for any blacklisted domain.
  * If a question name matches, return 1 to drop.
  */
 static int filter_check_dns(const unsigned char *data, size_t len) {
     if (len < 12) return 0;  // too short for DNS header
     uint16_t qdcount = ntohs(*(uint16_t *)(data + 4));
     size_t offset = 12;
     for (uint16_t i = 0; i < qdcount; i++) {
         // parse QNAME
         char qname[DOMAIN_MAX_LEN] = {0};
         size_t qlen = 0;
         while (offset < len) {
             uint8_t labellen = data[offset++];
             if (labellen == 0) break;
             if (offset + labellen > len || qlen + labellen + 1 >= DOMAIN_MAX_LEN)
                 return 0;
             memcpy(qname + qlen, data + offset, labellen);
             qlen += labellen;
             qname[qlen++] = '.';
             offset += labellen;
         }
         if (qlen && qname[qlen - 1] == '.') qname[qlen - 1] = '\0';
         // skip QTYPE + QCLASS
         offset += 4;
         // check blacklist
         pthread_mutex_lock(&mtx);
         for (filter_entry_t *e = head; e; e = e->next) {
             if (strstr(qname, e->domain)) {
                 pthread_mutex_unlock(&mtx);
                 return 1;
             }
         }
         pthread_mutex_unlock(&mtx);
     }
     return 0;
 }
 
 /**
  * Inspect HTTP payload for a Host: header matching the blacklist.
  */
 static int filter_check_http(const unsigned char *data, size_t len) {
     const char *hdr = "Host:";
     size_t hdrlen = strlen(hdr);
     for (size_t i = 0; i + hdrlen < len; i++) {
         if (memcmp(data + i, hdr, hdrlen) == 0) {
             const unsigned char *p = data + i + hdrlen;
             while (*p == ' ' && (size_t)(p - data) < len) p++;
             size_t j = 0;
             while (j + (size_t)(p - data) < len && p[j] != '\r' && p[j] != ':')
                 j++;
             char host[DOMAIN_MAX_LEN] = {0};
             size_t copy = j < DOMAIN_MAX_LEN - 1 ? j : DOMAIN_MAX_LEN - 1;
             memcpy(host, p, copy);
             host[copy] = '\0';
             pthread_mutex_lock(&mtx);
             for (filter_entry_t *e = head; e; e = e->next) {
                 if (strstr(host, e->domain)) {
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
 
 /**
  * Stub for TLS ClientHello SNI parsing.
  * Full implementation would parse the TLS record and handshake.
  */
 static int filter_check_tls_sni(const unsigned char *data, size_t len) {
     // TODO: implement SNI extraction
     return 0;
 }
 
 /**
  * Top-level filter function: given L4 proto and pointer/length,
  * decide whether to drop the packet.
  */
 int filter_should_drop(uint8_t proto, const void *l4, size_t l4len) {
     if (proto == IPPROTO_UDP) {
         const struct udphdr *u = l4;
         uint16_t dport = ntohs(u->dest);
         const unsigned char *payload = (const unsigned char*)l4 + sizeof(*u);
         size_t payload_len = l4len - sizeof(*u);
         if (dport == 53 && filter_check_dns(payload, payload_len)) {
             return 1;
         }
     }
     else if (proto == IPPROTO_TCP) {
         const struct tcphdr *t = l4;
         uint16_t dport = ntohs(t->dest);
         size_t hdrlen = t->doff * 4;
         // Drop HTTP SYN immediately
         if (t->syn && !t->ack && dport == 80) {
             return 1;
         }
         const unsigned char *payload = (const unsigned char*)l4 + hdrlen;
         size_t payload_len = l4len - hdrlen;
         if (dport == 80 && filter_check_http(payload, payload_len)) {
             return 1;
         }
         if (dport == 443 && filter_check_tls_sni(payload, payload_len)) {
             return 1;
         }
     }
     else if (proto == IPPROTO_ICMP) {
         // Optionally implement domain->IP mapping + ICMP drop
     }
     return 0;  // pass
 }
 