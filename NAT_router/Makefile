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
	iptables-legacy -I INPUT -i enp1s0f0 -p tcp --dport 49152:65535 -j DROP

tests: test-ping test-dns 
	@echo "Running tests..."

test-ping:
	ping -c 10 8.8.8.8

test-dns:
	nslookup www.youtube.com

# test-curl:
# 	curl -O https://link.testfile.org/500MB
# 	sha256sum 500MB | grep -q e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
# 		&& echo "OK" || echo "FAIL"
