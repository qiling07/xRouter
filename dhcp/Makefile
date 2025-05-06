CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

TARGETS = dhcp_server 

SRCS_SERVER = dhcp_server.c dhcp_packet.c addr_pool.c
OBJS_SERVER = $(SRCS_SERVER:.c=.o)


all: $(TARGETS)

dhcp_server: $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_SERVER) $(TARGETS)
