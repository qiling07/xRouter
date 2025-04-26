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

uint16_t fix_port_range(uint16_t p) {
    return (p % (65535 - 49152)) + 49152;
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
    e->is_static = 0;

    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);

    entry_count++;

    // if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    //     uint16_t port;
    //     do {
    //         port = random_port();
    //     } while (is_ext_port_taken(port, proto));
    //     e->ext_port = port;
    // } else {
    //     e->ext_port = int_port;
    // }

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        uint16_t port = fix_port_range(int_port);
        // If the chosen port/id is already taken, pick a random one
        if (is_ext_port_taken(port, proto)) {
            do {
                port = fix_port_range(port + 1);
            } while (is_ext_port_taken(port, proto));
        }
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

void nat_lookup_and_remove(uint32_t ip, uint16_t port, uint8_t proto, int reverse){
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);
    struct nat_entry *entry = NULL;
    if (!reverse) {
        unsigned idx = hash_internal(ip, port, proto);
        for (struct nat_entry *e = nat_internal[idx]; e; e = e->int_next) {
            if (e->int_ip == ip && e->int_port == port && e->proto == proto) {
                entry = e;
            }
        }
    } else {
        unsigned idx = hash_external(port, proto);
        for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
            if (e->ext_port == port && e->proto == proto) {
                entry = e;
            }
        }
        
    }
    if((!entry)){
        pthread_rwlock_unlock(&nat_external_rwlock);
        pthread_rwlock_unlock(&nat_internal_rwlock);
        return;
    }
    if((entry->int_fin!=1)||(entry->ext_fin!=1)||(entry->last_ack!=1)){
        pthread_rwlock_unlock(&nat_external_rwlock);
        pthread_rwlock_unlock(&nat_internal_rwlock);
        return;
    }
    bool found_internal = false, found_external = false;
    
    entry_count--;
    // Remove from internal hash table\n
    unsigned i_idx = hash_internal(entry->int_ip, entry->int_port, entry->proto);
    struct nat_entry **pp = &nat_internal[i_idx];
    while (*pp) {
        if (*pp == entry) {
            *pp = (*pp)->int_next;
            found_internal = true;
            break;
        }
        pp = &(*pp)->int_next;
    }
    // Remove from external hash table\n
    unsigned ex_idx = hash_external(entry->ext_port, entry->proto);
    struct nat_entry **qp = &nat_external[ex_idx];
    while (*qp) {
        if (*qp == entry) {
            *qp = (*qp)->ext_next;
            found_external = true;
            break;
        }
        qp = &(*qp)->ext_next;
    }
    // Only decrement and free if we actually removed something
    free(entry);

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
            if ((*pp)->is_static) {
                pp = &(*pp)->int_next;
                continue;
            }
            if (now - (*pp)->ts > NAT_TTL) {
                entry_count--;
                struct nat_entry *old = *pp;
                *pp = old->int_next;
                // Remove from external hash table
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

// Create a static port forwarding entry that will not time out
struct nat_entry *nat_add_port_forward(uint32_t int_ip, uint16_t int_port,
                                       uint32_t ext_if_ip, uint16_t ext_port,
                                       uint8_t proto) {
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);
    if (is_ext_port_taken(ext_port, proto) || ext_port < 49152 || ext_port > 65535) {
        pthread_rwlock_unlock(&nat_external_rwlock);
        pthread_rwlock_unlock(&nat_internal_rwlock);
        return NULL;
    }
    
    struct nat_entry *e = (struct nat_entry *)calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    e->int_ip = int_ip;
    e->int_port = int_port;
    e->ext_ip = ext_if_ip;
    e->ext_port = ext_port;
    e->proto = proto;
    e->ts = time(NULL);
    e->is_static = 1;

    entry_count++;

    // Insert into internal hash table
    unsigned i_idx = hash_internal(int_ip, int_port, proto);
    e->int_next = nat_internal[i_idx];
    nat_internal[i_idx] = e;

    // Insert into external hash table
    unsigned e_idx = hash_external(ext_port, proto);
    e->ext_next = nat_external[e_idx];
    nat_external[e_idx] = e;

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);

    return e;
}

int nat_delete_port_forward(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint16_t ext_port, uint8_t proto) {
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);

    // 1) Find and unlink from external table
    unsigned e_idx = hash_external(ext_port, proto);
    struct nat_entry **prev_ext = &nat_external[e_idx];
    struct nat_entry *e = NULL;
    while (*prev_ext) {
        if ((*prev_ext)->ext_ip   == ext_if_ip &&
            (*prev_ext)->ext_port == ext_port &&
            (*prev_ext)->proto    == proto &&
            (*prev_ext)->int_ip   == int_ip &&
            (*prev_ext)->int_port == int_port &&
            (*prev_ext)->is_static)
        {
            e = *prev_ext;
            *prev_ext = e->ext_next;
            break;
        }
        prev_ext = &(*prev_ext)->ext_next;
    }

    if (!e) {
        // nothing to delete
        pthread_rwlock_unlock(&nat_external_rwlock);
        pthread_rwlock_unlock(&nat_internal_rwlock);
        return -1;
    }

    // 2) Unlink from internal table
    unsigned i_idx = hash_internal(e->int_ip, e->int_port, proto);
    struct nat_entry **prev_int = &nat_internal[i_idx];
    while (*prev_int) {
        if (*prev_int == e) {
            *prev_int = e->int_next;
            break;
        }
        prev_int = &(*prev_int)->int_next;
    }

    // 3) Free and decrement count
    free(e);
    entry_count--;

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
    return 0;
}

void print_nat_table(int static_only = 0) {
    printf("NAT Table:\n");
    printf("--------------------------------------------------------------------------------\n");
    // Added a “Static” column before Last Activity
    printf("%-15s %-8s %-15s %-8s %-8s %-8s %-20s\n",
           "Internal IP", "Iport", "External IP", "Eport",
           "Proto",       "Static", "Last Activity");

    pthread_rwlock_rdlock(&nat_internal_rwlock);
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        for (struct nat_entry *e = nat_internal[i]; e; e = e->int_next) {
            // If user requested only static entries, skip non-static ones
            if (static_only && !e->is_static) 
                continue;

            char internal_ip_str[INET_ADDRSTRLEN];
            char external_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &e->int_ip, internal_ip_str, sizeof(internal_ip_str));
            inet_ntop(AF_INET, &e->ext_ip, external_ip_str, sizeof(external_ip_str));

            // Proto string
            char proto_str[6];
            if (e->proto == IPPROTO_TCP)      strcpy(proto_str, "TCP");
            else if (e->proto == IPPROTO_UDP) strcpy(proto_str, "UDP");
            else if (e->proto == IPPROTO_ICMP)strcpy(proto_str, "ICMP");
            else                               snprintf(proto_str, sizeof(proto_str), "%u", e->proto);

            // Static flag
            const char *static_str = e->is_static ? "yes" : "no";

            // Last activity timestamp
            char time_buf[20];
            struct tm *tm_info = localtime(&e->ts);
            if (tm_info)
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            else
                strcpy(time_buf, "N/A");

            // Print row with the new Static column
            printf("%-15s %-8u %-15s %-8u %-8s %-8s %-20s\n",
                   internal_ip_str,
                   ntohs(e->int_port),
                   external_ip_str,
                   ntohs(e->ext_port),
                   proto_str,
                   static_str,
                   time_buf);
        }
    }
    pthread_rwlock_unlock(&nat_internal_rwlock);

    printf("--------------------------------------------------------------------------------\n");
}

void get_nat_table_string(char *buf, size_t bufsize, int static_only = 0) {
    int offset = 0;
    offset += snprintf(buf + offset, bufsize - offset, "NAT Table:\n");
    offset += snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
    offset += snprintf(buf + offset, bufsize - offset, "%-15s %-8s %-15s %-8s %-8s %-8s %-20s\n", "Internal IP", "Iport", "External IP", "Eport", "Proto", "Static", "Last Activity");

    pthread_rwlock_rdlock(&nat_internal_rwlock);  // Read lock while printing
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        for (struct nat_entry *e = nat_internal[i]; e != NULL; e = e->int_next) {
            // If user requested only static entries, skip non-static ones
            if (static_only && !e->is_static) 
                continue;
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
            // Static flag
            const char *static_str = e->is_static ? "yes" : "no";
            char time_buf[26];
            struct tm *tm_info = localtime(&(e->ts));
            if (tm_info != NULL) {
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
            } else {
                strcpy(time_buf, "N/A");
            }
            offset += snprintf(buf + offset, bufsize - offset, "%-15s %-8d %-15s %-8d %-8s %-8s %-20s\n",
                               internal_ip_str, e->int_port, external_ip_str, e->ext_port, proto_str, static_str, time_buf);
            if (offset >= bufsize) {
                pthread_rwlock_unlock(&nat_internal_rwlock);
                return;
            }
        }
    }
    pthread_rwlock_unlock(&nat_internal_rwlock);

    snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
}

// Clear all NAT entries and reset the table
void nat_reset() {
    // Acquire write locks on both tables
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);

    // Free all entries in the internal table
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        struct nat_entry *e = nat_internal[i];
        while (e) {
            struct nat_entry *next = e->int_next;
            free(e);
            e = next;
        }
        nat_internal[i] = NULL;
    }

    // Clear all entries in the external table (pointers already freed)
    for (int i = 0; i < NAT_TABLE_SIZE; i++) {
        nat_external[i] = NULL;
    }

    // Reset entry count
    entry_count = 0;

    // Release locks
    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
}

