#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"   // Change if NAT router is at another address
#define SERVER_PORT 9999
#define BUFFER_SIZE 16384

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s PRINT_NAT_TABLE|RESET_NAT_TABLE\n", argv[0]);
        return EXIT_FAILURE;
    }
    char *message = argv[1];


    int sockfd;
    struct sockaddr_in server_addr;
    char recv_buf[BUFFER_SIZE];
    socklen_t addr_len = sizeof(server_addr);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/ Address not supported\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send request");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Sent %s request to NAT router admin server.\n", message);

    // Wait for the response (blocking call)
    int n = recvfrom(sockfd, recv_buf, sizeof(recv_buf) - 1, 0, NULL, NULL);
    if (n < 0) {
        perror("Failed to receive response");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    recv_buf[n] = '\0';

	if (strcmp(message, "PRINT_NAT_TABLE") == 0) {
		printf("NAT Table received:\n%s\n", recv_buf);
	} else if (strcmp(message, "RESET_NAT_TABLE") == 0) {
		printf("NAT Table reset confirmation received:\n%s\n", recv_buf);
	} else {
		printf("Unknown command: %s\n", message);
		printf("Response: %s\n", recv_buf);
	}

    close(sockfd);
    return 0;
}
