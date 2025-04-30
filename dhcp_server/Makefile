CC = gcc
CFLAGS = -Wall -Wextra -g

TARGETS = dhcp_server manager_client

SRCS_SERVER = dhcp_server.c dhcp_packet.c addr_pool.c
OBJS_SERVER = $(SRCS_SERVER:.c=.o)

SRCS_MANAGER = manager_client.c
OBJS_MANAGER = $(SRCS_MANAGER:.c=.o)

all: $(TARGETS)

dhcp_server: $(OBJS_SERVER)
	$(CC) $(CFLAGS) -o $@ $^

manager_client: $(OBJS_MANAGER)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_SERVER) $(OBJS_MANAGER) $(TARGETS)
