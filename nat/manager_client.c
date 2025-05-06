/**
 * manager.c – Management tool for the NAT-ROUTER
 *
 * Supports the following commands:
 *   print_nat             —— Print the current NAT table (PRINT_NAT_TABLE)
 *   reset_nat             —— Reset the NAT table (RESET_NAT_TABLE)
 *   filter_add <domain> <ip>  —— Add a domain filter rule (ADD_FILTER <domain> <ip>)
 *   filter_del <domain> <ip>  —— Delete a domain filter rule (DEL_FILTER <domain> <ip>)
 *   show_filters          —— Show all domain filter rules (SHOW_FILTERS)
 *   forward <internal_ip> <internal_port> <external_port>  —— Set up port forwarding rule (PORT_FORWARD)
 *   unforward <internal_ip> <internal_port> <external_port>  —— Cancel port forwarding rule (PORT_FORWARD)
 *   show_forwarding       —— Show forwarding rule (PORT_FORWARD)
 *   latency <network/CIDR>  —— Probe latency to each internal host (LATENCY)
 *
 * Usage:
 *   ./manager_client <command> [domain]
 * Examples:
 *   ./manager_client print_nat
 *   ./manager_client reset_nat
 *   ./manager_client filter_add example.com 192.168.20.10
 *   ./manager_client filter_del example.com 192.168.20.10
 *   ./manager_client show_filters
 *   ./manager_client forward 192.168.20.10 8080 80
 *   ./manager_client unforward 192.168.20.10 8080 80
 *   ./manager_client show_forwarding
 *   ./manager_client latency 192.168.0.1/24
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 
 #define SERVER_IP       "127.0.0.1"   // Change to the corresponding IP if the router is running on another address
 #define SERVER_PORT     9999
 #define MAX_BUFFER      16384
 #define CMD_MAX_LEN     512
 
// Print usage help
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <command> [domain]\n"
        "Commands:\n"
        "  print_nat            Print NAT table\n"
        "  reset_nat            Reset NAT table\n"
        "  filter_add   <domain> <ip>  Add domain filter rule\n"
        "  filter_del   <domain> <ip>  Delete domain filter rule\n"
        "  show_filters             Show all domain filter rules\n"
        "  forward <internal_ip> <internal_port> <external_port>   Set up port forwarding rule (PORT_FORWARD)\n"
        "  unforward <internal_ip> <internal_port> <external_port>   Delete port forwarding rule (PORT_FORWARD)\n"
        "  show_forwarding   Show forwarding rule (PORT_FORWARD)\n"
        "  latency          Probe latency to each internal host (LATENCY)\n",
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

 typedef struct {
    uint32_t int_ip;
    uint16_t int_port;
    uint16_t ext_port;
} port_forward_info;
 
 int main(int argc, char *argv[]) {
     char command[CMD_MAX_LEN] = {0};
     size_t command_len = -1;
 
     if (argc < 2) {
         print_usage(argv[0]);
         return EXIT_FAILURE;
     }
 
    // Construct request string based on the first argument
     if (strcmp(argv[1], "print_nat") == 0) {
         snprintf(command, sizeof(command), "PRINT_NAT_TABLE");
     }
     else if (strcmp(argv[1], "reset_nat") == 0) {
         snprintf(command, sizeof(command), "RESET_NAT_TABLE");
     }
     else if (strcmp(argv[1], "filter_add") == 0) {
         if (argc != 4) {
             fprintf(stderr, "Error: 'filter_add' requires a domain AND ip argument\n");
             print_usage(argv[0]);
             return EXIT_FAILURE;
         }
         snprintf(command, sizeof(command), "ADD_FILTER %s %s", argv[2], argv[3]);
     }
     else if (strcmp(argv[1], "filter_del") == 0) {
         if (argc != 4) {
             fprintf(stderr, "Error: 'filter_del' requires a domain AND ip argument\n");
             print_usage(argv[0]);
             return EXIT_FAILURE;
         }
         snprintf(command, sizeof(command), "DEL_FILTER %s %s", argv[2], argv[3]);
     }
    else if (strcmp(argv[1], "show_filters") == 0) {
        snprintf(command, sizeof(command), "SHOW_FILTERS");
    }
    else if (strcmp(argv[1], "forward") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: 'forward' requires <internal_ip> <internal_port> <external_port>\n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        port_forward_info pf;
        // Parse and validate internal IP
        pf.int_ip = inet_addr(argv[2]);
        if (pf.int_ip == INADDR_NONE) {
            fprintf(stderr, "Invalid internal IP address: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
        // Parse ports
        pf.int_port = htons((uint16_t)atoi(argv[3]));
        pf.ext_port = htons((uint16_t)atoi(argv[4]));

        printf("Setting up port forwarding: %s:%d -> %d\n",
               inet_ntoa(*(struct in_addr *)&pf.int_ip),
               ntohs(pf.int_port),
               ntohs(pf.ext_port));

        // Build binary request buffer
        command_len = strlen("PORT_FORWARD ") + sizeof(pf);
        memcpy(command, "PORT_FORWARD ", 13);
        memcpy(command + 13, &pf, sizeof(pf));
    }
    else if (strcmp(argv[1], "unforward") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: 'unforward' requires <internal_ip> <internal_port> <external_port>\n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        port_forward_info pf;
        // Parse and validate internal IP
        pf.int_ip = inet_addr(argv[2]);
        if (pf.int_ip == INADDR_NONE) {
            fprintf(stderr, "Invalid internal IP address: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
        // Parse ports
        pf.int_port = htons((uint16_t)atoi(argv[3]));
        pf.ext_port = htons((uint16_t)atoi(argv[4]));

        printf("Deleting port forwarding: %s:%d -> %d\n",
               inet_ntoa(*(struct in_addr *)&pf.int_ip),
               ntohs(pf.int_port),
               ntohs(pf.ext_port));

        // Build binary request buffer
        command_len = strlen("DEL_FORWARD ") + sizeof(pf);
        memcpy(command, "DEL_FORWARD ", 12);
        memcpy(command + 12, &pf, sizeof(pf));
    }
    else if (strcmp(argv[1], "latency") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Error: 'latency' requires <network/CIDR>\n");
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        snprintf(command, sizeof(command), "LATENCY %s", argv[2]);
        command_len = strlen(command);
    }
    else if (strcmp(argv[1], "show_forwarding") == 0) {
        snprintf(command, sizeof(command), "PRINT_FORWARD");
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
 