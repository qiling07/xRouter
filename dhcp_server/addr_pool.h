#ifndef ADDR_POOL_H
#define ADDR_POOL_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

struct binding
{
    uint32_t ip;    // host byte order
    uint8_t mac[6];
    time_t start_time;
    uint32_t lease_time;    // in seconds
    uint8_t is_leased;  // 0 for not leased, 1 for leased and 2 for offered but not accepted yet
};

struct addr_pool
{
    uint32_t start_ip;  // host byte order
    uint32_t end_ip;    // host byte order
    uint32_t pool_size;

    // binding pool
    struct binding *bindings;
    pthread_t expire_thread;    // check expiration time
};

struct addr_pool* init_addr_pool(const char *start, const char * end, uint32_t size);

void release_addr_pool(struct addr_pool *pool);

struct binding* get_binding_with_mac(struct addr_pool *pool, uint8_t status, uint8_t c_mac[6]);
struct binding* offer_ip(struct addr_pool *pool, const uint8_t c_mac[6]);
void cancel_offer(struct addr_pool *pool, const uint8_t c_mac[6]);
struct binding* allocate_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6], uint32_t l_time);
struct binding* release_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6]);
struct binding* try_renew(struct addr_pool *pool, uint32_t ip, const uint8_t c_mac[6], uint32_t l_time);

#endif