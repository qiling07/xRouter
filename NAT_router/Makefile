CC = g++
CFLAGS = -fpermissive
SRC = nat_router.c table.c debug_print.c utils.c
TARGET = nat_router


OBJ = nat_router

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o
