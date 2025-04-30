#include "table.h"
#include <pthread.h>

size_t entry_count = 0;
struct nat_entry *nat_internal[NAT_TABLE_SIZE] = {0};
struct nat_entry *nat_external[NAT_TABLE_SIZE] = {0};
pthread_rwlock_t nat_internal_rwlock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t nat_external_rwlock = PTHREAD_RWLOCK_INITIALIZER;


static inline unsigned hash_internal(uint32_t ip, uint16_t port, uint8_t proto) {
    return ((ip ^ port ^ proto) % NAT_TABLE_SIZE);
}

static inline unsigned hash_external(uint16_t port, uint8_t proto) {
    return ((port ^ proto) % NAT_TABLE_SIZE);
}

uint16_t fix_port_range(uint16_t p) {
    return (p % AVAILABLE_PORTS) + MIN_PORT;
}

// before calling this function, make sure to lock the nat_external_rwlock
bool is_ext_port_taken(uint16_t ext_port, uint8_t proto) {
    unsigned idx = hash_external(ext_port, proto);
    for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
        if (e->ext_port == ext_port && e->proto == proto) {
            return true;
        }
    }
    return false;
}


#ifdef USE_EBPF
#include <bpf/libbpf.h>
// #include <linux/bpf_helpers.h>
#include <linux/bpf.h>


int nat_map_fd = -1;
int ifindex_map_fd = -1;
struct bpf_object *bpf_obj = NULL;
int table_init(const char *bpf_obj_path, const char *int_if, const char *ext_if)
{
    struct bpf_object *obj;
    obj = bpf_object__open_file(bpf_obj_path, NULL);
    assert(obj && "Fail to open BPF object file");

    if (bpf_object__load(obj)) 
        assert(false && "Fail to load BPF object file into kernel");
    
    // find the map by section name “nat_map”
    nat_map_fd = bpf_object__find_map_fd_by_name(obj, "nat_map");
    assert(nat_map_fd >= 0 && "Fail to find map nat_map");

    // find and populate devmap
    ifindex_map_fd = bpf_object__find_map_fd_by_name(obj, "ifindex_map");
    assert(ifindex_map_fd >= 0 && "Fail to find map ifindex_map");

    // lookup kernel ifindices by name
    __u32 idx0 = 0, idx1 = 1;
    __u32 ext_idx = if_nametoindex(ext_if);
    __u32 int_idx = if_nametoindex(int_if);
    assert(ext_idx > 0 && int_idx > 0 && "Fail to find ifindex");

    // slot 0 → ext, slot 1 → int
    bpf_map_update_elem(ifindex_map_fd, &idx0, &ext_idx, BPF_ANY);
    bpf_map_update_elem(ifindex_map_fd, &idx1, &int_idx, BPF_ANY);

    // keep object alive for attach later
    bpf_obj = obj;

    printf("Table init done!\n");

    return 0;
}

void add_xdp_nat_entry(uint32_t int_ip, uint16_t int_port, uint32_t ext_ip, uint16_t ext_port, uint8_t proto) {
    {
        struct nat_key k = { .ip = int_ip, .port = int_port, .proto = proto };
        struct nat_val v = { .ip = ext_ip, .port = ext_port, .last_used = 0};
        bpf_map_update_elem(nat_map_fd, &k, &v, BPF_ANY);
    }

    {
        struct nat_key k = { .ip = ext_ip, .port = ext_port, .proto = proto };
        struct nat_val v = { .ip = int_ip, .port = int_port, .last_used = 0};
        bpf_map_update_elem(nat_map_fd, &k, &v, BPF_ANY);
    }
}


void del_xdp_nat_entry(uint32_t int_ip, uint16_t int_port, uint32_t ext_ip, uint16_t ext_port, uint8_t proto) {
    struct nat_key k1 = { .ip = int_ip, .port = int_port, .proto = proto };
    struct nat_key k2 = { .ip = ext_ip, .port = ext_port, .proto = proto };
    bpf_map_delete_elem(nat_map_fd, &k1);
    bpf_map_delete_elem(nat_map_fd, &k2);
}

uint64_t get_time_xdp_nat_entry(uint32_t int_ip, uint16_t int_port, uint32_t ext_ip, uint16_t ext_port, uint8_t proto) {
    struct nat_key k1 = { .ip = int_ip, .port = int_port, .proto = proto };
    struct nat_key k2 = { .ip = ext_ip, .port = ext_port, .proto = proto };
    struct nat_val v1, v2;
    if (bpf_map_lookup_elem(nat_map_fd, &k1, &v1) != 0)
        return 0;
    if (bpf_map_lookup_elem(nat_map_fd, &k2, &v2) != 0)
        return 0;
    return v1.last_used > v2.last_used ? v1.last_used : v2.last_used;
}

void reset_xdp_nat_entry() {
    uint8_t key[sizeof(struct nat_key)];
    uint8_t next_key[sizeof(struct nat_key)];

    // Start with the first key in the map
    if (bpf_map_get_next_key(nat_map_fd, NULL, key) != 0) {
        // Map is already empty
        return;
    }

    // Iterate through all keys and delete them
    do {
        if (bpf_map_delete_elem(nat_map_fd, key) != 0) {
            perror("Failed to delete element from BPF map");
        }
    } while (bpf_map_get_next_key(nat_map_fd, key, next_key) == 0 && (memcpy(key, next_key, sizeof(key)), 1));
}

#endif

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

struct nat_binding entry_to_binding(struct nat_entry *e) {
    struct nat_binding binding;
    if (e) {
        binding.is_valid = true;
        binding.int_ip = e->int_ip;
        binding.int_port = e->int_port;
        binding.ext_ip = e->ext_ip;
        binding.ext_port = e->ext_port;
        binding.proto = e->proto;
    } else {
        binding.is_valid = false;
    }
    return binding;
}

struct nat_binding nat_lookup_outbound(uint32_t src_ip, uint16_t src_port, 
    uint32_t dst_ip, uint16_t dst_port, uint8_t proto, bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst) 
{
    struct nat_binding binding = entry_to_binding(NULL);
    unsigned idx = hash_internal(src_ip, src_port, proto);

    pthread_rwlock_rdlock(&nat_internal_rwlock);
    for (struct nat_entry *e = nat_internal[idx]; e; e = e->int_next) {
        // loose check
        if (src_ip == e->int_ip && src_port == e->int_port 
            && proto == e->proto) {} 
        else continue;

        // strict check for non-static bindings
        if ((dst_ip == e->dst_ip && dst_port == e->dst_port)
            || e->is_static) {
            e->ts = time(NULL);

            // if TCP, update the connection status
            if ((!e->is_static) && proto == IPPROTO_TCP) {
                if (is_tcp_ack && (e->tcp_status & 0b011) == 0b011) e->tcp_status |= 0b100;
                if (is_tcp_fin) {
                    e->tcp_status |= 0b001;
#ifdef USE_EBPF
                    del_xdp_nat_entry(e->int_ip, e->int_port, e->ext_ip, e->ext_port, e->proto);
#endif
                }
                if (is_tcp_rst) e->tcp_status |= 0b111;
            }

            binding = entry_to_binding(e);

            pthread_rwlock_unlock(&nat_internal_rwlock);
            return binding;
        }
    }
    pthread_rwlock_unlock(&nat_internal_rwlock);
    return binding;
}

struct nat_binding nat_lookup_inbound(uint32_t src_ip, uint16_t src_port, 
    uint32_t dst_ip, uint16_t dst_port, uint8_t proto, bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst) 
{
    struct nat_binding binding = entry_to_binding(NULL);
    unsigned idx = hash_external(dst_port, proto);

    pthread_rwlock_rdlock(&nat_external_rwlock);
    for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
        // loose check
        if (dst_ip == e->ext_ip && dst_port == e->ext_port
            && proto == e->proto) {}
        else continue;
        
        // strict check for non-static bindings)
        if (proto == IPPROTO_ICMP) {
            if (src_ip == e->dst_ip
                || e->is_static) {
                e->ts = time(NULL);
                // 
                binding = entry_to_binding(e);

                pthread_rwlock_unlock(&nat_external_rwlock);
                return binding;
            }
        }
        else {
            if ((src_ip == e->dst_ip && src_port == e->dst_port)
                || e->is_static) {
                e->ts = time(NULL);
                
                // if TCP, update the connection status
                if ((!e->is_static) && proto == IPPROTO_TCP) {
                    if (is_tcp_ack && (e->tcp_status & 0b11) == 0b11) e->tcp_status |= 0b100;
                    if (is_tcp_fin) {
                        e->tcp_status |= 0b010;
#ifdef USE_EBPF
                        del_xdp_nat_entry(e->int_ip, e->int_port, e->ext_ip, e->ext_port, e->proto);
#endif
                    }
                    if (is_tcp_rst) e->tcp_status |= 0b111;
                }

                binding = entry_to_binding(e);

                pthread_rwlock_unlock(&nat_external_rwlock);
                return binding;
            }
        }
    }
    pthread_rwlock_unlock(&nat_external_rwlock);
    return binding;
}

struct nat_binding nat_create_binding(uint32_t src_ip, uint16_t src_port, 
    uint32_t dst_ip, uint16_t dst_port, uint8_t proto, uint32_t ext_if_ip) 
{
    struct nat_binding binding = entry_to_binding(NULL);
    assert(entry_count < NAT_TABLE_SIZE && "TODO: NAT table is full");
    
    struct nat_entry * e = (struct nat_entry *)calloc(1, sizeof(*e));
    assert(e != NULL);

    // initialize the new entry
    e->int_ip = src_ip;
    e->int_port = src_port;
    e->dst_ip = dst_ip;
    e->dst_port = dst_port;
    e->proto = proto;
    e->tcp_status = 0;


    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);
    
    e->ext_ip = ext_if_ip;
    e->ext_port = fix_port_range(dst_port);
    while (is_ext_port_taken(e->ext_port, proto)) {
        e->ext_port = fix_port_range(e->ext_port + 1);
    }
    e->ts = time(NULL);
    e->is_static = 0;

    // Insert into internal hash table
    unsigned i_idx = hash_internal(src_ip, src_port, proto);
    e->int_next = nat_internal[i_idx];
    nat_internal[i_idx] = e;

    // Insert into external hash table\n
    unsigned e_idx = hash_external(e->ext_port, proto);
    e->ext_next = nat_external[e_idx];
    nat_external[e_idx] = e;

    binding = entry_to_binding(e);

#ifdef USE_EBPF
    add_xdp_nat_entry(e->int_ip, e->int_port, e->ext_ip, e->ext_port, e->proto);
#endif

    entry_count++;
    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);

    return binding;
}

struct nat_binding nat_lookup_or_create_outbound(uint32_t src_ip, uint16_t src_port, 
    uint32_t dst_ip, uint16_t dst_port, uint8_t proto, uint32_t ext_if_ip, bool is_tcp_fin, bool is_tcp_ack, bool is_tcp_rst) 
{
    struct nat_binding e = nat_lookup_outbound(src_ip, src_port, dst_ip, dst_port, proto, is_tcp_fin, is_tcp_ack, is_tcp_rst);
    if (e.is_valid) return e;

    // If not found, create a new entry
    e = nat_create_binding(src_ip, src_port, dst_ip, dst_port, proto, ext_if_ip);
    return e; 
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

int nat_remove(struct nat_entry *e) {
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

// void nat_lookup_and_remove(uint32_t ip, uint16_t port, uint8_t proto, int reverse){
//     pthread_rwlock_wrlock(&nat_internal_rwlock);
//     pthread_rwlock_wrlock(&nat_external_rwlock);
//     struct nat_entry *entry = NULL;
//     if (!reverse) {
//         unsigned idx = hash_internal(ip, port, proto);
//         for (struct nat_entry *e = nat_internal[idx]; e; e = e->int_next) {
//             if (e->int_ip == ip && e->int_port == port && e->proto == proto) {
//                 entry = e;
//             }
//         }
//     } else {
//         unsigned idx = hash_external(port, proto);
//         for (struct nat_entry *e = nat_external[idx]; e; e = e->ext_next) {
//             if (e->ext_port == port && e->proto == proto) {
//                 entry = e;
//             }
//         }
        
//     }
//     if((!entry)){
//         pthread_rwlock_unlock(&nat_external_rwlock);
//         pthread_rwlock_unlock(&nat_internal_rwlock);
//         return;
//     }
//     if((entry->int_fin!=1)||(entry->ext_fin!=1)||(entry->last_ack!=1)){
//         pthread_rwlock_unlock(&nat_external_rwlock);
//         pthread_rwlock_unlock(&nat_internal_rwlock);
//         return;
//     }

//     // bool found_internal = false, found_external = false;
    
//     // entry_count--;
//     // // Remove from internal hash table\n
//     // unsigned i_idx = hash_internal(entry->int_ip, entry->int_port, entry->proto);
//     // struct nat_entry **pp = &nat_internal[i_idx];
//     // while (*pp) {
//     //     if (*pp == entry) {
//     //         *pp = (*pp)->int_next;
//     //         found_internal = true;
//     //         break;
//     //     }
//     //     pp = &(*pp)->int_next;
//     // }
//     // // Remove from external hash table\n
//     // unsigned ex_idx = hash_external(entry->ext_port, entry->proto);
//     // struct nat_entry **qp = &nat_external[ex_idx];
//     // while (*qp) {
//     //     if (*qp == entry) {
//     //         *qp = (*qp)->ext_next;
//     //         found_external = true;
//     //         break;
//     //     }
//     //     qp = &(*qp)->ext_next;
//     // }
//     // // Only decrement and free if we actually removed something
//     // free(entry);

//     pthread_rwlock_unlock(&nat_external_rwlock);
//     pthread_rwlock_unlock(&nat_internal_rwlock);

// }

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
            // handle different situations
            // 1. closed TCP
            // 2. long-idle TCP/UDP/ICMP
            uint8_t tcp_status = (*pp)->tcp_status;
            time_t inactive_time = now - (*pp)->ts;
            uint8_t proto = (*pp)->proto;
            bool outdated = ((tcp_status & 0b100) == 0b100 && inactive_time > TCP_CLOSED_TTL) ||
                            ((tcp_status & 0b100) == 0 && proto == IPPROTO_TCP && inactive_time > TCP_INACTIVE_TTL) ||
                            (proto != IPPROTO_TCP && inactive_time > NAT_INACTIVE_TTL);
#ifdef USE_EBPF
            if (outdated) {
                time_t last_used = get_time_xdp_nat_entry((*pp)->int_ip, (*pp)->int_port, 
                    (*pp)->ext_ip, (*pp)->ext_port, (*pp)->proto);
                if (last_used > (*pp)->ts) {
                    (*pp)->ts = last_used;
                    inactive_time = now - (*pp)->ts;
                    outdated = ((tcp_status & 0b100) == 0b100 && inactive_time > TCP_CLOSED_TTL) ||
                            ((tcp_status & 0b100) == 0 && proto == IPPROTO_TCP && inactive_time > TCP_INACTIVE_TTL) ||
                            (proto != IPPROTO_TCP && inactive_time > NAT_INACTIVE_TTL);
                }
            }
#endif
            if (outdated) {
                entry_count--;
                // printf("Deleting entry: proto : %u, tcp_status: %u, inactive time: %u\n", proto, tcp_status, inactive_time);
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
// all inputs should be in host byte order
struct nat_binding nat_add_port_forward(uint32_t int_ip, uint16_t int_port,
                                       uint32_t ext_if_ip, uint16_t ext_port,
                                       uint8_t proto) {
    struct nat_binding binding = entry_to_binding(NULL);
    pthread_rwlock_wrlock(&nat_internal_rwlock);
    pthread_rwlock_wrlock(&nat_external_rwlock);
    if (is_ext_port_taken(ext_port, proto) || ext_port < MIN_PORT || ext_port > MAX_PORT) {
        pthread_rwlock_unlock(&nat_external_rwlock);
        pthread_rwlock_unlock(&nat_internal_rwlock);
        return binding;
    }
    
    struct nat_entry *e = (struct nat_entry *)calloc(1, sizeof(*e));
    assert(e != NULL);
    
    e->int_ip = int_ip;
    e->int_port = int_port;
    
    e->dst_ip = 0;
    e->dst_port = 0;
    
    e->ext_ip = ext_if_ip;
    e->ext_port = ext_port;
    
    e->proto = proto;
    e->ts = time(NULL);    
    e->is_static = 1;
    e->tcp_status = 0;

    entry_count++;

    // Insert into internal hash table
    unsigned i_idx = hash_internal(int_ip, int_port, proto);
    e->int_next = nat_internal[i_idx];
    nat_internal[i_idx] = e;

    // Insert into external hash table
    unsigned e_idx = hash_external(ext_port, proto);
    e->ext_next = nat_external[e_idx];
    nat_external[e_idx] = e;

    binding = entry_to_binding(e);

#ifdef USE_EBPF
    add_xdp_nat_entry(e->int_ip, e->int_port, e->ext_ip, e->ext_port, e->proto);
#endif

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);

    return binding;
}

// all inputs should be in host byte order
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

#ifdef USE_EBPF
    del_xdp_nat_entry(e->int_ip, e->int_port, e->ext_ip, e->ext_port, e->proto);
#endif

    // 3) Free and decrement count
    free(e);
    entry_count--;

    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
    return 0;
}

void get_entry_string(char *buf, size_t bufsize, int static_only, struct nat_entry *e) {
    int offset = 0;
    offset += snprintf(buf + offset, bufsize - offset, "NAT Table:\n");
    offset += snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
    offset += snprintf(buf + offset, bufsize - offset, "%-15s %-8s %-15s %-8s %-8s %-8s %-20s\n", "Internal IP", "Iport", "External IP", "Eport", "Proto", "Static", "Last Activity");

    pthread_rwlock_rdlock(&nat_internal_rwlock);  // Read lock while printing

    // If user requested only static entries, skip non-static ones
    if (static_only && !e->is_static) return;
    char internal_ip_str[INET_ADDRSTRLEN];
    char external_ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(uint32_t){ htonl(e->int_ip) }, internal_ip_str, INET_ADDRSTRLEN) == NULL) {
        strcpy(internal_ip_str, "N/A");
    }
    if (inet_ntop(AF_INET, &(uint32_t){ htonl(e->ext_ip) }, external_ip_str, INET_ADDRSTRLEN) == NULL) {
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

    pthread_rwlock_unlock(&nat_internal_rwlock);

    snprintf(buf + offset, bufsize - offset, "--------------------------------------------------------------------------------\n");
}

void get_nat_table_string(char *buf, size_t bufsize, int static_only) {
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
            // if (inet_ntop(AF_INET, &(e->int_ip), internal_ip_str, INET_ADDRSTRLEN) == NULL) {
            //     strcpy(internal_ip_str, "N/A");
            // }
            // if (inet_ntop(AF_INET, &(e->ext_ip), external_ip_str, INET_ADDRSTRLEN) == NULL) {
            //     strcpy(external_ip_str, "N/A");
            // }
            if (inet_ntop(AF_INET, &(uint32_t){ htonl(e->int_ip) }, internal_ip_str, INET_ADDRSTRLEN) == NULL) {
                strcpy(internal_ip_str, "N/A");
            }
            if (inet_ntop(AF_INET, &(uint32_t){ htonl(e->ext_ip) }, external_ip_str, INET_ADDRSTRLEN) == NULL) {
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

void print_nat_table(int static_only) {
    char buf[16384];
    get_nat_table_string(buf, sizeof(buf), static_only);
    printf("%s", buf);
}

void print_nat_entry(struct nat_entry *e, int static_only) {
    char buf[16384];
    get_entry_string(buf, sizeof(buf), static_only, e);
    printf("%s", buf);
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

#ifdef USE_EBPF
    reset_xdp_nat_entry();
#endif

    // Release locks
    pthread_rwlock_unlock(&nat_external_rwlock);
    pthread_rwlock_unlock(&nat_internal_rwlock);
}

