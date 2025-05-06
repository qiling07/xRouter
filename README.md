# xRouter
## Key Features
| Category              | Additional Features                                                                                                                                                                                                       | Source Code                                                                                                                         |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| **Management Portal** | - Remote Login via TCP (`telnet`/`nc router 8888`)<br>- Secure Credentials (salted hash + `reset_credentials`)<br>- IP Access Controller (whitelist in `allowed_networks.json`)                                          | - `NAT_router/nat-portal.py`<br>- `NAT_router/manager_client.c`<br>- `dhcp-server/manager_client.c`                                   |
| **DHCP**              | - Lease Time Setting (`set <MAC> <lease_time>`)<br>- IP Reservation / Static IP (`reserve <MAC> <IP>`)                                                                                                                   | - `dhcp-server/dhcp_server.c`<br>- `dhcp-server/addr_pool.c`                                                                          |
| **NAT**               | - Content Control (per-host, per-domain filtering)<br>- PMTUD & IP Fragmentation support<br>- Port Forwarding & Hairpinning<br>- ICMP Error Message Handling<br>- Multithreading & eBPF/XDP optimizations                   | - `NAT_router/nat_router.c`<br>- `NAT_router/manager_client.c`<br>- `NAT_router/filter/filter.c`<br>- `NAT_router/nat_kern.c`       |
## Architecture Overview
![overview](https://github.com/qiling07/xrouter/architecture.png)
## Environment Setup
## How to run
- Build and run the DHCP server. Configure `dhcp/dhcp.conf` as needed.
  ```
  cd dhcp_server
  make
  ./dhcp_server
  ```
- Build and run the NAT server. 
  ```
  cd NAT_router
  make
  make config
  ./[nat_router|nat_router_ebpf] LAN_IF WAN_IF
  ```
   
## Performance
```
netperf -H 128.105.145.222 -t UDP_RR -l 10 -- -m 64 -M 64 -P 0 -o THROUGHPUT,P50_LATENCY,P99_LATENCY,STDDEV_LATENCY
iperf -c 128.105.145.222 -P 30 | tail -n 2
yt-dlp https://www.youtube.com/watch?v=3MBv6PIsCBg --cookies ~/cookies.txt
```

## Known Issues
