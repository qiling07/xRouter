#include "table.h"
#include <pthread.h>


struct nat_entry *nat_internal[NAT_TABLE_SIZE] = {0};
struct nat_entry *nat_external[NAT_TABLE_SIZE] = {0};
pthread_rwlock_t nat_internal_rwlock = PTHREAD_RWLOCK_INITIALIZER;  // Initialize the lock
pthread_rwlock_t nat_external_rwlock = PTHREAD_RWLOCK_INITIALIZER;  // Initialize the lock

size_t entry_count = 0;


static inline unsigned hash_internal(uint32_t ip, uint16_t port, uint8_t proto) {
    return ((ip ^ port ^ proto) % NAT_TABLE_SIZE);
}

static inline unsigned hash_external(uint16_t port, uint8_t proto) {
    return ((port ^ proto) % NAT_TABLE_SIZE);
}

uint16_t random_port() {
    return (rand() % (65535 - 49152)) + 49152;
}

struct nat_entry *nat_lookup(uint32_t ip, uint16_t port, uint8_t proto, int reverse) {

    if (!reverse) {
        pthread_rwlock_rdlock(&nat_internal_rwlock);
        unsigned idx = hash_internal(ip, port, proto);
        for (struct nat_entry *e = nat_internal[idx]; e; e = e->int_next) {
            if (e->int_ip == ip && e->int_port == port && e->proto == proto) {
                pthread_rwlock_unlock(&nat_internal_rwlock);
                return e;
            }
        }
        pthread_rwlock_unlock(&nat_internal_rwlock);
    } else {
        pthread_rwlock_rdlock(&nat_external_rwlock);
        unsigned idx = hash_external(port, proto);
        for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
            if (e->ext_port == port && e->proto == proto) {
                pthread_rwlock_unlock(&nat_external_rwlock);
                return e;
            }
        }
        pthread_rwlock_unlock(&nat_external_rwlock);
    }
    return NULL;
}

int is_ext_port_taken(uint16_t ext_port, uint8_t proto) {
    unsigned idx = hash_external(ext_port, proto);
    for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
        if (e->ext_port == ext_port && e->proto == proto) {
            return 1;
        }
    }
    
    return 0;
}

struct nat_entry *nat_create(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint8_t proto) {
    struct nat_entry *e = (struct nat_entry *)calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->int_ip = int_ip;
    e->int_port = int_port;
    e->ext_ip = ext_if_ip;
    e->proto = proto;
    e->ts = time(NULL);

    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);

    entry_count++;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        uint16_t port;
        do {
            port = random_port();
        } while (is_ext_port_taken(port, proto));
        e->ext_port = port;
    } else {
        e->ext_port = int_port;
    }

    // Insert into internal hash table\n
    unsigned i_idx = hash_internal(int_ip, int_port, proto);
    e->int_next = nat_internal[i_idx];
    nat_internal[i_idx] = e;

    // Insert into external hash table\n
    unsigned e_idx = hash_external(e->ext_port, proto);
    e->ext_next = nat_external[e_idx];
    nat_external[e_idx] = e;

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);

    return e;
}

static void nat_remove(struct nat_entry *e) {
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);

    entry_count--;

    // Remove from internal hash table\n
    unsigned i_idx = hash_internal(e->int_ip, e->int_port, e->proto);
    struct nat_entry **pp = &nat_internal[i_idx];
    while (*pp) {
        if (*pp == e) {
            *pp = (*pp)->int_next;
            break;
        }
        pp = &(*pp)->int_next;
    }
    // Remove from external hash table\n
    unsigned ex_idx = hash_external(e->ext_port, e->proto);
    struct nat_entry **qp = &nat_external[ex_idx];
    while (*qp) {
        if (*qp == e) {
            *qp = (*qp)->ext_next;
            break;
        }
        qp = &(*qp)->ext_next;
    }
    free(e);

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
}

void nat_gc() {
    time_t now = time(NULL);
    
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry **pp = &nat_internal[i];
        while (*pp) {
            if (now - (*pp)->ts > NAT_TTL) {
                entry_count--;
                struct nat_entry *old = *pp;
                *pp = old->int_next;
                // Remove from external hash table\n
                unsigned ex_idx = hash_external(old->ext_port, old->proto);
                struct nat_entry **qp = &nat_external[ex_idx];
                while (*qp) {
                    if (*qp == old) {
                        *qp = (*qp)->ext_next;
                        break;
                    }
                    qp = &(*qp)->ext_next;
                }
                free(old);
            } else {
                pp = &(*pp)->int_next;
            }
        }
    }
    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
}

void print_nat_table() {
    printf("NAT Table:\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("%-15s %-8s %-15s %-8s %-8s %-20s\n", "Internal IP", "Iport", "External IP", "Eport", "Proto", "Last Activity");

    pthread_rwlock_rdlock(&nat_internal_rwlock);  // Read lock while printing
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        for (struct nat_entry *e = nat_internal[i]; e != NULL; e = e->int_next) {
            char internal_ip_str[INET_ADDRSTRLEN];
            char external_ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &(e->int_ip), internal_ip_str, INET_ADDRSTRLEN) == NULL) {
                strcpy(internal_ip_str, "N/A");
            }
            if (inet_ntop(AF_INET, &(e->ext_ip), external_ip_str, INET_ADDRSTRLEN) == NULL) {
                strcpy(external_ip_str, "N/A");
            }
            char proto_str[10];
            if (e->proto == IPPROTO_TCP) {
                strcpy(proto_str, "TCP");
            } else if (e->proto == IPPROTO_UDP) {
                strcpy(proto_str, "UDP");
            } else if (e->proto == IPPROTO_ICMP) {
                strcpy(proto_str, "ICMP");
            } else {
                snprintf(proto_str, sizeof(proto_str), "%d", e->proto);
            }
            char time_buf[26];
            struct tm *tm_info = localtime(&(e->ts));
            if (tm_info != NULL) {
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strcpy(time_buf, "N/A");
            }
            printf("%-15s %-8d %-15s %-8d %-8s %-20s\n", internal_ip_str, e->int_port, external_ip_str, e->ext_port, proto_str, time_buf);
        }
    }
    pthread_rwlock_unlock(&nat_internal_rwlock);

    printf("--------------------------------------------------------------------------------\n");
}

void get_nat_table_string(char *buf, size_t bufsize) {
    int offset = 0;
    offset += snprintf(buf + offset, bufsize - offset, "NAT Table:\n");
    offset += snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
    offset += snprintf(buf + offset, bufsize - offset, "%-15s %-8s %-15s %-8s %-8s %-20s\n", "Internal IP", "Iport", "External IP", "Eport", "Proto", "Last Activity");

    pthread_rwlock_rdlock(&nat_internal_rwlock);  // Read lock while printing
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        for (struct nat_entry *e = nat_internal[i]; e != NULL; e = e->int_next) {
            char internal_ip_str[INET_ADDRSTRLEN];
            char external_ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &(e->int_ip), internal_ip_str, INET_ADDRSTRLEN) == NULL) {
                strcpy(internal_ip_str, "N/A");
            }
            if (inet_ntop(AF_INET, &(e->ext_ip), external_ip_str, INET_ADDRSTRLEN) == NULL) {
                strcpy(external_ip_str, "N/A");
            }
            char proto_str[10];
            if (e->proto == IPPROTO_TCP) {
                strcpy(proto_str, "TCP");
            } else if (e->proto == IPPROTO_UDP) {
                strcpy(proto_str, "UDP");
            } else if (e->proto == IPPROTO_ICMP) {
                strcpy(proto_str, "ICMP");
            } else {
                snprintf(proto_str, sizeof(proto_str), "%d", e->proto);
            }
            char time_buf[26];
            struct tm *tm_info = localtime(&(e->ts));
            if (tm_info != NULL) {
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strcpy(time_buf, "N/A");
            }
            offset += snprintf(buf + offset, bufsize - offset, "%-15s %-8d %-15s %-8d %-8s %-20s\n",
                               internal_ip_str, e->int_port, external_ip_str, e->ext_port, proto_str, time_buf);
            if (offset >= bufsize) {
                pthread_rwlock_unlock(&nat_internal_rwlock);
                return;
            }
        }
    }
    pthread_rwlock_unlock(&nat_internal_rwlock);

    snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
}

