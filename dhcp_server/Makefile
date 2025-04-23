CC = gcc
CFLAGS = -Wall -Wextra -g -pthread

TARGET = dhcp_server

SRCS = dhcp_server.c dhcp_packet.c addr_pool.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
