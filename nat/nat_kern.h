#ifndef __NAT_KERNEL_H
#define __NAT_KERNEL_H

#include <stdint.h>

struct nat_key {
    uint32_t ip;
    uint16_t port;
    uint8_t  proto;
};

struct nat_val {
    uint32_t ip;
    uint16_t port;
    uint64_t last_used; // in nanoseconds
};

#endif
