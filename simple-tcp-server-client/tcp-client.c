#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ------------------------------------------------
   Global variables (as specified by the assignment)
   ------------------------------------------------ */
int s;                /* Global socket descriptor */
size_t nbytes = 0;    /* Global number of bytes to send/receive */
unsigned char strt;   /* Global "start" byte (0–255) */
unsigned char incr;   /* Global "increment" (prime from {1,3,5,7,11,13,17}) */

/* ------------------------------------------------
   From previous examples: client_snd() and client_rec()
   ------------------------------------------------ */

void client_snd(int s, size_t nbytes, unsigned char strt, unsigned char incr) {
    unsigned char buff[1024];
    size_t buffer_index = 0;
    size_t bytes_generated = 0;

    unsigned char current_val = strt;

    while (bytes_generated < nbytes) {
        buff[buffer_index++] = current_val;
        bytes_generated++;
        current_val = (unsigned char)((current_val + incr) % 256);

        if (buffer_index == sizeof(buff)) {
            if (send(s, buff, buffer_index, 0) < 0) {
                perror("send");
                return;
            }
            buffer_index = 0;
        }
    }
    /* Send remaining data in buffer if any */
    if (buffer_index > 0) {
        if (send(s, buff, buffer_index, 0) < 0) {
            perror("send");
            return;
        }
    }
    /* Signal we're done sending (EOF on the write side). */
    if (shutdown(s, SHUT_WR) < 0) {
        perror("shutdown");
    }
}

void client_rec(int s, size_t nbytes, unsigned char strt, unsigned char incr) {
    unsigned char buff[1024];
    size_t total_received = 0;
    unsigned char next_expected = strt;

    while (1) {
        ssize_t rc = recv(s, buff, sizeof(buff), 0);
        if (rc < 0) {
            perror("recv");
            return;
        }
        if (rc == 0) {
            /* EOF */
            break;
        }
        for (ssize_t i = 0; i < rc; i++) {
            if (total_received >= nbytes) {
                fprintf(stderr,
                        "Error: Received more than %zu bytes (extra byte %u)\n",
                        nbytes, buff[i]);
                return;
            }
            if (buff[i] != next_expected) {
                fprintf(stderr,
                        "Mismatch at byte #%zu. Expected %u, got %u\n",
                        total_received, next_expected, buff[i]);
                return;
            }
            total_received++;
            next_expected = (unsigned char)((next_expected + incr) % 256);
        }
    }

    if (total_received < nbytes) {
        fprintf(stderr,
                "Error: EOF reached after %zu bytes, expected %zu\n",
                total_received, nbytes);
        return;
    }

    printf("All %zu bytes received and verified successfully.\n", nbytes);
}

/* ------------------------------------------------
   Thread wrappers so we can pass them to pthreads
   ------------------------------------------------ */
void *sender_thread(void *arg) {
    /* Simply call client_snd with our global variables */
    client_snd(s, nbytes, strt, incr);
    return NULL;
}

void *receiver_thread(void *arg) {
    /* Simply call client_rec with our global variables */
    client_rec(s, nbytes, strt, incr);
    return NULL;
}

/* ------------------------------------------------
   Main function: parse arguments, connect, run threads
   ------------------------------------------------ */
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <host> <port> <number_of_bytes>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *host = argv[1];
    char *port_str = argv[2];
    nbytes = strtoull(argv[3], NULL, 10);

    /* 1) Randomize strt (0–255) and incr (prime from set {1,3,5,7,11,13,17}) */
    srand((unsigned)time(NULL));
    strt = (unsigned char)(rand() % 256);
    unsigned char prime_set[] = {1, 3, 5, 7, 11, 13, 17};
    incr = prime_set[rand() % (sizeof(prime_set)/sizeof(prime_set[0]))];

    /* 2) Create and connect a TCP socket to host:port */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;       /* or AF_UNSPEC for IPv4/IPv6 */
    hints.ai_socktype = SOCK_STREAM;   
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        perror("socket");
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(s);
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(res);

    printf("Connected to %s:%s\n", host, port_str);
    printf("nbytes=%zu, strt=%u, incr=%u\n", nbytes, strt, incr);

    /* 3) Create two threads for sending and receiving. */
    pthread_t tid_snd, tid_rec;
    if (pthread_create(&tid_snd, NULL, sender_thread, NULL) != 0) {
        perror("pthread_create (snd)");
        close(s);
        exit(EXIT_FAILURE);
    }
    if (pthread_create(&tid_rec, NULL, receiver_thread, NULL) != 0) {
        perror("pthread_create (rec)");
        close(s);
        exit(EXIT_FAILURE);
    }

    /* 4) Wait for both threads to complete */
    pthread_join(tid_snd, NULL);
    pthread_join(tid_rec, NULL);

    /* 5) Print result */
    printf("Total bytes sent and received: %zu\n", nbytes);

    /* 6) Clean up and exit */
    close(s);
    return 0;
}
