# Compiler settings
CC            := g++
CFLAGS        := -fpermissive -pthread -Ifilter

BPF_CLANG     := clang
BPF_CFLAGS    := -O2 -g -target bpf
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

# Source files
BPF_SRC       := nat_kern.c
BPF_OBJ       := nat_kern.o

USR_SRC       := nat_router.c table.c utils.c debug_print.c filter/filter.c latency.c

# Phony targets
.PHONY: all clean

# Default: build everything
all: nat_kern.o nat_router nat_router_ebpf

# 1) eBPF object
nat_kern.o: $(BPF_SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2) User-space router (no eBPF)
nat_router: $(USR_SRC)
	$(CC) $(CFLAGS) $(USR_SRC) -o $@

# 3) Router with eBPF support (links BPF object and libbpf)
nat_router_ebpf: $(USR_SRC) $(BPF_OBJ)
	$(CC) -D USE_EBPF $(LIBBPF_CFLAGS) $(CFLAGS) $(USR_SRC) -o $@ $(LIBBPF_LIBS)

config:
	# prevent linux from sending RST packets 
	# https://stackoverflow.com/questions/15477427/why-kernel-sent-rst-to-a-remote-tcp-server-after-the-machine-receiving-a-syn-ack
	sudo iptables -I INPUT -i enp1s0f0 -p tcp --dport 49152:65535 -j DROP
	sudo iptables -I INPUT -i enp6s0f0 -p tcp --dport 49152:65535 -j DROP
	# sudo iptables-legacy -A FORWARD -o enp1s0f0 -s 10.10.1.2 -j DROP

	# avoid intererence with NAT PTMUD and IP fragmentation
	sudo ethtool -K enp1s0f0 gro off gso off tso off
	sudo ethtool -K enp6s0f0 gro off gso off tso off

# Clean up all build artifacts
clean:
	rm -f $(BPF_OBJ) nat_router nat_router_ebpf
