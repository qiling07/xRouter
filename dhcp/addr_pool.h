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

struct mac_lease_time
{
    uint8_t active;
    uint8_t mac[6];
    uint32_t lease_time;
};

struct reservation
{
    uint8_t active;
    uint8_t mac[6];
    uint32_t ip; // host order
};

#define MAX_MANAGEMENT_NUM 32
struct pool_management
{
    struct mac_lease_time mlt[MAX_MANAGEMENT_NUM];   // host byte order
    struct reservation reservations[MAX_MANAGEMENT_NUM];

    pthread_mutex_t mlt_lock;
    pthread_mutex_t reservations_lock;
};

struct addr_pool
{
    uint32_t start_ip;  // host byte order
    uint32_t end_ip;    // host byte order
    uint32_t pool_size;

    // binding pool
    struct binding *bindings;
    pthread_t expire_thread;    // check expiration time

    struct pool_management manage;
};

uint32_t ip_str_to_host_order(const char *ip_str);
uint32_t ip_str_to_network_order(const char *ip_str);

struct addr_pool* init_addr_pool(const char *start, const char * end, uint32_t size);

void release_addr_pool(struct addr_pool *pool);

struct binding* get_binding_with_mac(struct addr_pool *pool, uint8_t status, uint8_t c_mac[6]);
struct binding* offer_ip(struct addr_pool *pool, const uint8_t c_mac[6]);
void cancel_offer(struct addr_pool *pool, const uint8_t c_mac[6]);
struct binding* allocate_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6], uint32_t l_time);
struct binding* release_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6]);
struct binding* try_renew(struct addr_pool *pool, uint32_t ip, const uint8_t c_mac[6], uint32_t l_time);
struct mac_lease_time* get_mac_lease_time(struct addr_pool *pool, const uint8_t c_mac[6]);;
int8_t set_ip_lease_time(struct addr_pool *pool, const uint8_t c_mac[6], uint32_t l_time);
struct reservation* get_reservation_w_mac(struct addr_pool *pool, const uint8_t c_mac[6]);
struct reservation* get_reservation_w_ip(struct addr_pool *pool, const uint32_t ip);
int8_t set_reservation(struct addr_pool *pool, const uint8_t c_mac[6], uint32_t ip);
#endif