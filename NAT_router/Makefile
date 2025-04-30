CC = g++
CFLAGS = -fpermissive -pthread -Ifilter
SRC = nat_router.c table.c debug_print.c utils.c filter/filter.c latency.c
TARGET = nat_router 


OBJ = nat_router

all: $(TARGET) manager_client

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o

config:
	/usr/sbin/iptables -I INPUT -i enp0s3 -p tcp --dport 49152:65535 -j DROP
	sudo iptables-legacy -A FORWARD -o enp1s0f0 -s 10.10.1.2 -j DROP
	sudo ethtool -K enp1s0f0 gro off gso off tso off
	sudo ethtool -K enp6s0f0 gro off gso off tso off
