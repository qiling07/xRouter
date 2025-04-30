#include <unistd.h>
#include <netinet/in.h>
#include "addr_pool.h"



uint32_t ip_str_to_host_order(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 0;
    }
    return ntohl(addr.s_addr);
}
uint32_t ip_str_to_network_order(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip_str);
        return 0;
    }
    return addr.s_addr;
}


void* check_expiration(void *arg){
    struct addr_pool *pool = (struct addr_pool *)arg;
    while (1)
    {
        time_t current_time = time(NULL);

        for (uint32_t i = 0; i < pool->pool_size; ++i)
        {
            struct binding *b = &(pool->bindings[i]);
            if (b->is_leased == 1)
            {
                if (difftime(current_time, b->start_time) > b->lease_time)
                {
                    b->is_leased = 0;
                }
            }
        }
        sleep(10);
    }
}

struct addr_pool* init_addr_pool(const char *start, const char *end, uint32_t size){
    struct addr_pool *pool = (struct addr_pool*)malloc(sizeof(struct addr_pool));
    pool->start_ip = ip_str_to_host_order(start);
    pool->end_ip = ip_str_to_host_order(end);
    pool->pool_size = size;
    pool->bindings = (struct binding *)malloc(sizeof(struct binding) * size);
    for (int i = 0; i < size; i++)
    {
        pool->bindings[i].ip = pool->start_ip+i;
        pool->bindings[i].is_leased = 0;
        memset(pool->bindings[i].mac, 0, 6);
    }
    for (int i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        pool->manage.mlt[i].active = 0;
        pool->manage.reservations[i].active = 0;
    }
    pthread_mutex_init(&pool->manage.mlt_lock, NULL);
    pthread_mutex_init(&pool->manage.reservations_lock, NULL);
    pthread_create(&pool->expire_thread, NULL, check_expiration, pool);
    return pool;
}

// mutex lock on bindings need to be aquired before calling this function
// `status` parameter refers to `is_leased` in `struct binding` 
struct binding* get_binding_with_mac(struct addr_pool *pool, uint8_t status, uint8_t c_mac[6]){
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (pool->bindings[i].is_leased == status && memcmp(pool->bindings[i].mac, c_mac, 6) == 0)
        {
            return &(pool->bindings[i]);
        }
    }
    return NULL;
}

struct binding* offer_ip(struct addr_pool *pool, const uint8_t c_mac[6]){
    pthread_mutex_lock(&(pool->manage.reservations_lock));
    // check if there's a fixed ip for `c_mac`
    struct reservation* r = get_reservation_w_mac(pool, c_mac);
    if (r)
    {
        struct binding *b = &(pool->bindings[r->ip - pool->start_ip]);
        if (b->is_leased)
        {
            // TODO: what if the binding.mac == c_mac
            perror("An reserved IP is already assigned to another MAC address");
            exit(-1);
        }
        b->is_leased = 2;
        memcpy(b->mac, c_mac, 6);
        pthread_mutex_unlock(&(pool->manage.reservations_lock));
        return b;
    }

    int offered_n = -1;

    // check whether an IP is already allocated to the MAC address
    if (get_binding_with_mac(pool, 1, c_mac) != NULL)
    {
        // TODO: How to deal with this situation?
    }
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (pool->bindings[i].is_leased == 2 && offered_n == -1) offered_n = i;
        else if (pool->bindings[i].is_leased == 0)
        {
            pool->bindings[i].is_leased = 2;
            memcpy(pool->bindings[i].mac, c_mac, 6);
            pthread_mutex_unlock(&(pool->manage.reservations_lock));
            return &pool->bindings[i];
        }
    }
    if (offered_n == -1) {
        pthread_mutex_unlock(&(pool->manage.reservations_lock));
        return NULL;
    }
    pool->bindings[offered_n].is_leased = 2;
    memcpy(pool->bindings[offered_n].mac, c_mac, 6);
    pthread_mutex_unlock(&(pool->manage.reservations_lock));
    return &pool->bindings[offered_n];
}

void cancel_offer(struct addr_pool *pool, const uint8_t c_mac[6]){
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (pool->bindings[i].is_leased == 2 && memcmp(pool->bindings[i].mac, c_mac, 6) == 0)
        {
            pool->bindings[i].is_leased = 0;
            memcpy(pool->bindings[i].mac, 0, 6);
        }
    }
}

struct binding* allocate_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6], uint32_t l_time){
    pthread_mutex_lock(&(pool->manage.reservations_lock));
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (y_ip == pool->bindings[i].ip && pool->bindings[i].is_leased == 2 && memcmp(c_mac, pool->bindings[i].mac, 6) == 0)
        {
            pool->bindings[i].start_time = time(NULL);
            pool->bindings[i].lease_time = l_time;
            pool->bindings[i].is_leased = 1;
            pthread_mutex_unlock(&(pool->manage.reservations_lock));
            return &pool->bindings[i];
        }
    }
    pthread_mutex_unlock(&(pool->manage.reservations_lock));
    return NULL;
}

struct binding* release_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6]){
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (y_ip == pool->bindings[i].ip && pool->bindings[i].is_leased == 1 
            && memcmp(pool->bindings[i].mac, c_mac, 6) == 0)
        {
            pool->bindings[i].is_leased = 0;
            return &pool->bindings[i];
        }
    }
    return NULL;
}

void release_addr_pool(struct addr_pool *pool){
    free(pool->bindings);
    free(pool);
}

struct binding* try_renew(struct addr_pool *pool, uint32_t ip, const uint8_t c_mac[6], uint32_t l_time){
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (ip == pool->bindings[i].ip && pool->bindings[i].is_leased == 1 
            && memcmp(pool->bindings[i].mac, c_mac, 6) == 0)
        {
            pool->bindings[i].lease_time = l_time;
            return &pool->bindings[i];
        }
    }
    return NULL;
}

struct mac_lease_time* get_mac_lease_time(struct addr_pool *pool, const uint8_t c_mac[6]){
    for (int i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        if (pool->manage.mlt[i].active && memcmp(pool->manage.mlt[i].mac, c_mac, 6) == 0)
        {
            return &(pool->manage.mlt[i]);
        }
    }
    return NULL;
}

int8_t set_ip_lease_time(struct addr_pool *pool, const uint8_t c_mac[6], uint32_t l_time){
    struct mac_lease_time* mlt = get_mac_lease_time(pool, c_mac);
    if (mlt)
    {
        mlt->lease_time = l_time == 0? UINT32_MAX: l_time;
        return 1;
    }
    for (int i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        if (pool->manage.mlt[i].active == 0)
        {
            pool->manage.mlt[i].active = 1;
            pool->manage.mlt[i].lease_time = l_time == 0? UINT32_MAX: l_time;
            memcpy(pool->manage.mlt[i].mac, c_mac, 6);
            return 1;
        }
    }
    return 0;
}

// Need to acquire the reservations_lock before calling this function
struct reservation* get_reservation_w_mac(struct addr_pool *pool, const uint8_t c_mac[6]){
    for (size_t i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        if (pool->manage.reservations[i].active && memcmp(pool->manage.reservations[i].mac, c_mac, 6) == 0)
        {
            return &(pool->manage.reservations[i]);
        }
    }
    return NULL;
}

// Need to acquire the reservations_lock before calling this function
struct reservation* get_reservation_w_ip(struct addr_pool *pool, const uint32_t ip){
    for (size_t i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        if (pool->manage.reservations[i].active && pool->manage.reservations[i].ip == ip)
        {
            return &(pool->manage.reservations[i]);
        }
    }
    return NULL;
}


// Need to acquire the reservations_lock before calling this function
int8_t set_reservation(struct addr_pool *pool, const uint8_t c_mac[6], uint32_t ip){
    // check the IP address is in the IP pool
    if (pool->start_ip > ip || pool->end_ip < ip)
    {
        printf("The reserved IP address is not in the pool: start_ip = %u, end_ip = %u, ip = %u\n",
            pool->start_ip, pool->end_ip, ip);
        return 0;
    }
    // check whether the IP address is leased or not (We consider an IP is leased once it is offered)
    if (pool->bindings[ip - pool->start_ip].is_leased != 0)
    {
        printf("The IP address is already offered or assigned\n");
        return 0;
    }
    // check whether the IP address is already reserved
    struct reservation* r = get_reservation_w_ip(pool, ip);
    if (r != NULL)
    {
        if (memcmp(r->mac, c_mac, 6) == 0) return 1;
        printf("The IP address is already reserved\n");
        return 0;
    }
    // update ip?
    r = get_reservation_w_mac(pool, c_mac);
    if (r)
    {
        printf("Update IP address\n");
        r->ip = ip;
        return 1;
    }
    
    for (int i = 0; i < MAX_MANAGEMENT_NUM; i++)
    {
        if (pool->manage.reservations[i].active == 0)
        {
            pool->manage.reservations[i].active = 1;
            memcpy(pool->manage.reservations[i].mac, c_mac, 6);
            pool->manage.reservations[i].ip = ip;
            return 1;
        }
    }
    printf("reservations number reach the maximum\n");
    return 0;
}