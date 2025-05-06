# DHCP Server

This directory contains the DHCP server component of the xrouter project.

## Prerequisites

- GCC (or compatible C compiler)  
- GNU Make  
- Root privileges (required to bind to UDP port 67)

## Build

```bash
cd dhcp
make
```

This will produce the dhcp_server executable.

## Configuration

All runtime settings live in dhcp.conf (next to the binary). Edit it to match your network:

```
# Interfaces
ISP_interface    eth0
LAN_interface    eth1

# Network parameters
gateway          192.168.20.1
netmask          255.255.255.0
broadcast        192.168.20.255

# DNS and domain
domain_name      router.vm
dns_ip           8.8.8.8

# Address pool
start_ip         192.168.20.101
end_ip           192.168.20.200
pool_size        100

# Timers (in seconds)
lease_time       6000
rebinding_time   5000
renew_time       3000
```

Make sure dhcp.conf sits alongside dhcp_server when you run it.

## Run

```
sudo ./dhcp_server
```

The server binds to port 67 and listens on your LAN_interface for DHCP DISCOVER/REQUEST packets.

An admin thread listens on UDP port 9998. You can adjust leases or reservations without stopping the server. Refer to portal readme for more details.


## Cleanup

```
make clean
```
