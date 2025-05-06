#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Forward declaration of the tcp_echo function */
void tcp_echo(int s);

int main(int argc, char *argv[])
{
    /* 1) Check arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Convert port from string to integer */
    int port = atoi(argv[1]);
    if (port <= 0) {
        fprintf(stderr, "Error: invalid port number '%s'\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    /* 2) Create a TCP socket */
    int s1 = socket(AF_INET, SOCK_STREAM, 0);
    if (s1 < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Optional: set SO_REUSEADDR to help with quick restarts */
    int optval = 1;
    if (setsockopt(s1, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(s1);
        exit(EXIT_FAILURE);
    }

    /* 3) Bind the socket to INADDR_ANY on the specified port */
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port        = htons(port);

    if (bind(s1, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind");
        close(s1);
        exit(EXIT_FAILURE);
    }

    /* 4) Listen for incoming connections */
    if (listen(s1, 5) < 0) {
        perror("listen");
        close(s1);
        exit(EXIT_FAILURE);
    }

    printf("Echo server listening on port %d\n", port);

    /* 5) Repeatedly accept new connections and echo data */
    while (1) {
        struct sockaddr_in cliaddr;
        socklen_t cli_len = sizeof(cliaddr);

        int s2 = accept(s1, (struct sockaddr *)&cliaddr, &cli_len);
        if (s2 < 0) {
            perror("accept");
            continue;  /* Keep the server alive, try next connection */
        }

        /* Optionally log the client info */
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, sizeof(client_ip));
        printf("Accepted connection from %s:%d\n",
               client_ip, ntohs(cliaddr.sin_port));

        /* Handle the echo in a dedicated function */
        tcp_echo(s2);

        /* Close the connected socket after echoing */
        close(s2);
    }

    /* (Unreachable in this simple example, but good practice to clean up) */
    close(s1);
    return 0;
}

/* tcp_echo function */
void tcp_echo(int s)
{
    int byte_count = 0;
    unsigned char buff[4096];

    while (1)
    {
        ssize_t n = recv(s, buff, sizeof(buff), 0);
        if (n < 0) {
            perror("recv");
            return;
        }
        if (n == 0) {
            /* EOF from client */
            printf("Total bytes sent %d\n", byte_count);
            /* Signal EOF to client */
            if (shutdown(s, SHUT_WR) < 0) {
                perror("shutdown");
            }
            return;
        }

        byte_count += n;

        /* Echo back exactly what was received */
        ssize_t sent = send(s, buff, n, 0);
        if (sent < 0) {
            perror("send");
            return;
        }
        /* In real-world code, handle partial sends by looping until all n bytes are sent */
    }
}

