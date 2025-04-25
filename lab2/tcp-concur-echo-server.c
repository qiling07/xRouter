#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

/* Forward declaration of the tcp_echo function */
void *tcp_echo(void *arg);

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    if (port <= 0) {
        fprintf(stderr, "Error: invalid port number '%s'\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    int s1 = socket(AF_INET, SOCK_STREAM, 0);
    if (s1 < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(s1, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(s1);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    if (bind(s1, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(s1);
        exit(EXIT_FAILURE);
    }

    if (listen(s1, 5) < 0) {
        perror("listen");
        close(s1);
        exit(EXIT_FAILURE);
    }

    printf("Echo server listening on port %d\n", port);

    while (1) {
        struct sockaddr_in cliaddr;
        socklen_t cli_len = sizeof(cliaddr);

        int *s2 = malloc(sizeof(int));
        if (!s2) {
            perror("malloc");
            continue;
        }

        *s2 = accept(s1, (struct sockaddr *)&cliaddr, &cli_len);
        if (*s2 < 0) {
            perror("accept");
            free(s2);
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, sizeof(client_ip));
        printf("Accepted connection from %s:%d\n", client_ip, ntohs(cliaddr.sin_port));

        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_echo, s2) != 0) {
            perror("pthread_create");
            close(*s2);
            free(s2);
        } else {
            pthread_detach(thread);
        }
    }

    close(s1);
    return 0;
}

void *tcp_echo(void *arg)
{
    int s = *(int *)arg;
    free(arg);

    int byte_count = 0;
    unsigned char buff[4096];

    while (1)
    {
        ssize_t n = recv(s, buff, sizeof(buff), 0);
        if (n < 0) {
            perror("recv");
            break;
        }
        if (n == 0) {
            printf("Total bytes sent %d\n", byte_count);
            if (shutdown(s, SHUT_WR) < 0) {
                perror("shutdown");
            }
            break;
        }

        byte_count += n;

        ssize_t sent = send(s, buff, n, 0);
        if (sent < 0) {
            perror("send");
            break;
        }
    }

    close(s);
    return NULL;
}
