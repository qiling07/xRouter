# NAT Router

This directory contains the user-space NAT router component of the xrouter project. The router supports:
- SNAT for outbound TCP/UDP/ICMP flows
- DNAT for inbound replies and port forwarding
- Optional eBPF/XDP acceleration for high performance

## Prerequisites

- **C compiler** (GCC or Clang)  
- **Make**  
- **libbpf** (for eBPF build)  
  ```bash
  sudo apt-get update
  sudo apt-get install -y clang libbpf-dev pkg-config
  ```
- **Root privileges** (required for raw sockets and XDP)

## Build

From the `nat/` directory, run:

```bash
make
```

This creates three targets:
- `nat_kern.o`       – eBPF bytecode object  
- `nat_router`       – pure user-space router (no eBPF)  
- `nat_router_ebpf`  – router with eBPF/XDP support  

To remove build artifacts:

```bash
make clean
```

## Configuration

By default, the router reads interface IP, netmask, broadcast and MTU at startup—no additional config files are needed. However, before running:

1. **Disable offloading** to avoid large-packet issues:
   ```bash
   sudo ethtool -K <INT_IF> gro off gso off tso off
   sudo ethtool -K <EXT_IF> gro off gso off tso off
   ```

2. **Prevent kernel RST on high ports**:
   ```bash
   sudo iptables -I INPUT -i <EXT_IF> -p tcp --dport 49152:65535 -j DROP
   sudo iptables -I INPUT -i <INT_IF> -p tcp --dport 49152:65535 -j DROP
   ```

Replace `<INT_IF>` with your LAN interface (e.g., `eth1`), and `<EXT_IF>` with your WAN interface (e.g., `eth0`).

## Usage

### Number of Worker Threads

The router uses a thread pool for packet processing. By default, `NUM_WORKERS` is set to 4 in `nat_router.c`. Adjust and rebuild if needed.

### Run Without eBPF

```bash
sudo ./nat_router <int_if> <ext_if>
```

### Run With eBPF/XDP

```bash
sudo ./nat_router_ebpf <int_if> <ext_if>
```

- `<int_if>`: LAN interface name  
- `<ext_if>`: WAN interface name  

## Administration

An admin thread listens on UDP port **9999**. You can query or modify NAT state with `PRINT_NAT_TABLE` and `RESET_NAT_TABLE` commands. For more commands (filters, port forwarding, ...), see the portal README.


