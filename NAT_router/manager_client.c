/**
 * manager.c – 管理 NAT-ROUTER 的管理应用
 *
 * 支持以下命令：
 *   print             —— 打印当前 NAT 转发表 (PRINT_NAT_TABLE)
 *   add <domain>      —— 添加域名过滤规则 (ADD_FILTER <domain>)
 *   del <domain>      —— 删除域名过滤规则 (DEL_FILTER <domain>)
 *   show              —— 显示所有域名过滤规则 (SHOW_FILTERS)
 *
 * 用法：
 *   ./manager <command> [domain]
 * 例如：
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
 
 #define SERVER_IP       "127.0.0.1"   // 如果路由器运行在其它地址，这里改成对应的 IP
 #define SERVER_PORT     9999
 #define MAX_BUFFER      16384
 #define CMD_MAX_LEN     512
 
 // 打印使用帮助
 static void print_usage(const char *prog) {
     fprintf(stderr,
         "Usage: %s <command> [domain]\n"
         "Commands:\n"
         "  print            Print NAT table\n"
         "  add   <domain>   Add domain filter rule\n"
         "  del   <domain>   Delete domain filter rule\n"
         "  show             Show all domain filter rules\n",
         prog);
 }
 
 // 向路由器 admin 线程发送请求，并打印回复
 static int send_request(const char *request) {
     int sockfd, ret;
     struct sockaddr_in srv_addr;
     char recv_buf[MAX_BUFFER];
 
     // 1. 创建 UDP 套接字
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0) {
         perror("socket");
         return -1;
     }
 
     // 2. 准备目标地址
     memset(&srv_addr, 0, sizeof(srv_addr));
     srv_addr.sin_family = AF_INET;
     srv_addr.sin_port   = htons(SERVER_PORT);
     if (inet_pton(AF_INET, SERVER_IP, &srv_addr.sin_addr) != 1) {
         fprintf(stderr, "Invalid server IP: %s\n", SERVER_IP);
         close(sockfd);
         return -1;
     }
 
     // 3. 发送命令
     ret = sendto(sockfd,
                  request,
                  strlen(request),
                  0,
                  (struct sockaddr *)&srv_addr,
                  sizeof(srv_addr));
     if (ret < 0) {
         perror("sendto");
         close(sockfd);
         return -1;
     }
 
     // 4. 接收回复
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
 
     // 5. 打印回复
     printf("%s\n", recv_buf);
 
     close(sockfd);
     return 0;
 }
 
 int main(int argc, char *argv[]) {
     char command[CMD_MAX_LEN] = {0};
 
     if (argc < 2) {
         print_usage(argv[0]);
         return EXIT_FAILURE;
     }
 
     // 根据第一个参数选择组装请求字符串
     if (strcmp(argv[1], "print") == 0) {
         snprintf(command, sizeof(command), "PRINT_NAT_TABLE");
     }
     else if (strcmp(argv[1], "add") == 0) {
         if (argc != 3) {
             fprintf(stderr, "Error: 'add' requires a domain argument\n");
             print_usage(argv[0]);
             return EXIT_FAILURE;
         }
         snprintf(command, sizeof(command), "ADD_FILTER %s", argv[2]);
     }
     else if (strcmp(argv[1], "del") == 0) {
         if (argc != 3) {
             fprintf(stderr, "Error: 'del' requires a domain argument\n");
             print_usage(argv[0]);
             return EXIT_FAILURE;
         }
         snprintf(command, sizeof(command), "DEL_FILTER %s", argv[2]);
     }
     else if (strcmp(argv[1], "show") == 0) {
         snprintf(command, sizeof(command), "SHOW_FILTERS");
     }
     else {
         fprintf(stderr, "Unknown command: %s\n", argv[1]);
         print_usage(argv[0]);
         return EXIT_FAILURE;
     }
 
     // 发送并打印结果
     if (send_request(command) != 0) {
         fprintf(stderr, "Failed to execute command '%s'\n", command);
         return EXIT_FAILURE;
     }
 
     return EXIT_SUCCESS;
 }
 