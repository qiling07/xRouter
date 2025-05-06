# xRouter
## Key Features
## Architecture Overview
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
