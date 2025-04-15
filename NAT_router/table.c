#include "table.h"

struct nat_entry *nat_head = NULL;


uint16_t random_port() { return (rand() % (65535 - 49152)) + 49152; }


struct nat_entry *nat_lookup(uint32_t ip, uint16_t port, uint8_t proto, int reverse) {
    for (struct nat_entry *e = nat_head; e; e = e->next) {
        if (!reverse && e->int_ip == ip && e->int_port == port && e->proto == proto)
            return e;
        if (reverse && e->ext_port == port && e->proto == proto)
            return e;
    }
    return NULL;
}

int is_ext_port_taken(uint16_t ext_port, uint8_t proto) {
    for (struct nat_entry *e = nat_head; e; e = e->next) {
        if (e->proto == proto && e->ext_port == ext_port) {
            return 1;
        }
    }
    return 0;
}

struct nat_entry *nat_create(uint32_t int_ip, uint16_t int_port, uint32_t ext_if_ip, uint8_t proto) {
    struct nat_entry *e = (struct nat_entry *)calloc(1, sizeof(*e));
    e->int_ip = int_ip;
    e->int_port = int_port;
    e->ext_ip = ext_if_ip;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        uint16_t port;
        do {
            port = random_port();
        } while (is_ext_port_taken(port, proto));
        e->ext_port = port;
    } else {
        e->ext_port = int_port;
    }

    e->proto = proto;
    e->ts = time(NULL);

    e->next = nat_head;
    nat_head = e;
    return e;
}

void nat_gc() {
    time_t now = time(NULL);
    struct nat_entry **pp = &nat_head;
    while (*pp) {
        if (now - (*pp)->ts > NAT_TTL) {
            struct nat_entry *old = *pp;
            *pp = old->next;
            free(old);
        } else {
            pp = &(*pp)->next;
        }
    }
}

void print_nat_table() {}
