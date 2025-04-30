/**
 * manager.c – Management tool for the NAT-ROUTER
 *
 * Supports the following commands:
 *   print             —— Print the current NAT table (PRINT_NAT_TABLE)
 *   add <domain>      —— Add a domain filter rule (ADD_FILTER <domain>)
 *   del <domain>      —— Delete a domain filter rule (DEL_FILTER <domain>)
 *   show              —— Show all domain filter rules (SHOW_FILTERS)
 *
 * Usage:
 *   ./manager <command> [domain]
 * Examples:
 *   ./manager print
 *   ./manager add example.com
 *   ./manager del facebook.com
 *   ./manager show
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 
#define SERVER_IP       "127.0.0.1"   // Change to the corresponding IP if the router is running on another address
 #define SERVER_PORT     9998
 #define MAX_BUFFER      16384
 #define CMD_MAX_LEN     512
 
// Print usage help
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <command> [domain]\n"
        "Commands:\n"
        "  set <MAC_address> <lease_time>    Set lease time for a specific\n"
        "  reserve <MAC_address> <IP_address>    Reserve `IP_address` for `MAC_address`\n",
        prog);
}
 
// Send request to router's admin thread and print the response
 static int send_request(const char *request, size_t len) {
     int sockfd, ret;
     struct sockaddr_in srv_addr;
     char recv_buf[MAX_BUFFER];
 
    // 1. Create UDP socket
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0) {
         perror("socket");
         return -1;
     }
 
    // 2. Prepare destination address
     memset(&srv_addr, 0, sizeof(srv_addr));
     srv_addr.sin_family = AF_INET;
     srv_addr.sin_port   = htons(SERVER_PORT);
     if (inet_pton(AF_INET, SERVER_IP, &srv_addr.sin_addr) != 1) {
         fprintf(stderr, "Invalid server IP: %s\n", SERVER_IP);
         close(sockfd);
         return -1;
     }
 
    // 3. Send command
    if (len == -1) {
        len = strlen(request);
    }
     ret = sendto(sockfd,
                  request,
                  len,
                  0,
                  (struct sockaddr *)&srv_addr,
                  sizeof(srv_addr));
     if (ret < 0) {
         perror("sendto");
         close(sockfd);
         return -1;
     }
 
    // 4. Receive response
     ret = recvfrom(sockfd,
                    recv_buf,
                    sizeof(recv_buf) - 1,
                    0,
                    NULL,
                    NULL);
     if (ret < 0) {
         perror("recvfrom");
         close(sockfd);
         return -1;
     }
     recv_buf[ret] = '\0';
 
    // 5. Print response
     printf("%s\n", recv_buf);
 
     close(sockfd);
     return 0;
 }

 int main(int argc, char *argv[]) {
     char command[CMD_MAX_LEN] = {0};
     size_t command_len = -1;
 
     if (argc < 2) {
         print_usage(argv[0]);
         return EXIT_FAILURE;
     }
 
    // Construct request string based on the first argument
     if (strcmp(argv[1], "set") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: 'set' requires <MAC_address> <lease_time> \n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        
        uint8_t mac[6];
        uint32_t lease_time;

        // Parse MAC address
        if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
            fprintf(stderr, "Error: Invalid MAC address: %s\n", argv[2]);
            return EXIT_FAILURE;
        }

        // Parse lease time
        lease_time = (uint32_t)strtoul(argv[3], NULL, 10);

        printf("Setting up lease time: %02x:%02x:%02x:%02x:%02x:%02x %d\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            lease_time);

        // Build binary request buffer
        command_len = snprintf(command, sizeof(command),
            "SET_LEASE_TIME %02x:%02x:%02x:%02x:%02x:%02x %u",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            lease_time);
    }
    else if (strcmp(argv[1], "reserve") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: 'reserve' requires <MAC_address> <IP_address> \n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        
        uint8_t mac[6];

        // Parse MAC address
        if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
            fprintf(stderr, "Error: Invalid MAC address: %s\n", argv[2]);
            return EXIT_FAILURE;
        }

        struct in_addr ip_addr;

        if (inet_pton(AF_INET, argv[3], &ip_addr) != 1)
        {
            fprintf(stderr, "Error: Invalid IP address: %s\n", argv[2]);
            return EXIT_FAILURE;
        }

        printf("Reserve IP: %02x:%02x:%02x:%02x:%02x:%02x %s\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            argv[3]);

        // Build binary request buffer
        command_len = snprintf(command, sizeof(command),
            "RESERVE_IP %02x:%02x:%02x:%02x:%02x:%02x %s",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            argv[3]);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
 
    // Send request and print result
     if (send_request(command, command_len) != 0) {
         fprintf(stderr, "Failed to execute command '%s'\n", command);
         return EXIT_FAILURE;
     }
 
     return EXIT_SUCCESS;
 }