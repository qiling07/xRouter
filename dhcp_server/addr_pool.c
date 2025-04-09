#include <unistd.h>
#include <netinet/in.h>
#include "addr_pool.h"

void* check_expiration(void *arg){
    struct addr_pool *pool = (struct addr_pool *)arg;
    while (1)
    {
        time_t current_time = time(NULL);

        pthread_mutex_lock(&pool->bindings_lock);
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
        pthread_mutex_unlock(&pool->bindings_lock);

        sleep(10);
    }
}

struct addr_pool* init_addr_pool(const char *start, const char * end, uint32_t size){
    struct in_addr start_addr, end_addr;
    inet_aton(start, &start_addr);
    inet_aton(end, &end_addr);
    struct addr_pool *pool = (struct addr_pool*)malloc(sizeof(struct addr_pool));
    pool->start_ip = ntohl(start_addr.s_addr);
    pool->end_ip = ntohl(end_addr.s_addr);
    pool->pool_size = size;
    pool->bindings = (struct binding *)malloc(sizeof(struct binding) * size);
    for (int i = 0; i < size; i++)
    {
        pool->bindings[i].ip = pool->start_ip+i;
        pool->bindings[i].is_leased = 0;
    }
    pthread_mutex_init(&pool->bindings_lock, NULL);
    pthread_create(&pool->expire_thread, NULL, check_expiration, pool);
    return pool;
}

// mutex lock on bindings need to be aquired before calling this function
// `status` parameter refers to `is_leased` in `struct binding` 
struct binding* get_binding_with_ip(struct addr_pool *pool, uint8_t status, uint8_t c_mac[6]){
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
    int offered_n = -1;

    pthread_mutex_lock(&pool->bindings_lock);
    // check whether an IP is already allocated to the MAC address
    if (get_binding_with_ip(pool, 1, c_mac) != NULL)
    {
        // TODO: How to deal with this situation?
    }
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (pool->bindings[i].is_leased == 2 && offered_n == -1) offered_n = i;
        else if (pool->bindings[i].is_leased == 0)
        {
            pthread_mutex_unlock(&pool->bindings_lock);
            return &pool->bindings[i];
        }
    }
    pthread_mutex_unlock(&pool->bindings_lock);
    if (offered_n == -1) return NULL;
    return &pool->bindings[offered_n];
}

void cancel_offer(struct addr_pool *pool, const uint8_t c_mac[6]){
    pthread_mutex_lock(&pool->bindings_lock);
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (pool->bindings[i].is_leased == 2 && memcmp(pool->bindings[i].mac, c_mac, 6) == 0)
        {
            pool->bindings[i].is_leased = 0;
        }
    }
    pthread_mutex_unlock(&pool->bindings_lock);
}

struct binding* allocate_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6], uint32_t l_time){
    pthread_mutex_lock(&pool->bindings_lock);
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (ntohl(y_ip) == pool->bindings[i].ip && pool->bindings[i].is_leased != 1)
        {
            memcpy(pool->bindings[i].mac, c_mac, 6);
            pool->bindings[i].start_time = time(NULL);
            pool->bindings[i].lease_time = l_time;
            pool->bindings[i].is_leased = 1;
            pthread_mutex_unlock(&pool->bindings_lock);
            return &pool->bindings[i];
        }
    }
    pthread_mutex_unlock(&pool->bindings_lock);
    return NULL;
}

struct binding* release_ip(struct addr_pool *pool, uint32_t y_ip, const uint8_t c_mac[6]){
    pthread_mutex_lock(&pool->bindings_lock);
    for (int i = 0; i < pool->pool_size; i++)
    {
        if (ntohl(y_ip) == pool->bindings[i].ip && pool->bindings[i].is_leased == 1 
            && memcmp(pool->bindings[i].mac, c_mac, 6))
        {
            pool->bindings[i].is_leased = 0;
            pthread_mutex_unlock(&pool->bindings_lock);
            return &pool->bindings[i];
        }
    }
    pthread_mutex_unlock(&pool->bindings_lock);
    return NULL;
}

// TODO: consider whether we need a mutex lock on `bindings` or not

void release_addr_pool(struct addr_pool *pool){
    free(pool->bindings);
    free(pool);
}