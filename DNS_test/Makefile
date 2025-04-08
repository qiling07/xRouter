CC = g++
CFLAGS = -Wall -O2 -std=c++17
SRC = udp_dns_test.c
TARGET = udp_dns_test


OBJ = udp_dns_test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o
