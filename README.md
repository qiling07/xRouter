# xRouter
Our project implements a high-performance network router combining NAT and DHCP functionalities, designed to handle real-world traffic with efficiency and flexibility. The router performs standard NAPT operations with support for port forwarding and hairpinning, while the DHCP server supports IP leasing, reservations, and lease time configuration. The architecture includes both a fast eBPF/XDP kernel module for existing NAT sessions and a user-space module for complex cases, closely mirroring the software/hardware page table model in virtual memory systems.

Additional highlights include a secure, TCP-based management portal with credential protection and IP whitelisting, per-host/domain content filtering, and full support for PMTUD and IP fragmentation. Multithreading and eBPF acceleration provide a 3× throughput improvement and 50% latency reduction compared to the baseline. The system is validated across both virtual and bare-metal environments using tools like Netperf, iPerf, and real-world streaming benchmarks, demonstrating near-native performance even with NAT enabled.

## Key Features
| Category              | Additional Features       |
|-----------------------|---------------------------|
| **NAT**               | - PMTUD & IP Fragmentation support<br>- Port Forwarding & Hairpinning<br>- ICMP Error Message Handling<br>- Content Control<br>- Multithreading & **eBPF/XDP** optimizations               |
| **DHCP**              | - Lease Time Setting <br>- IP Reservation / Static IP        |
| **Management Portal** | - Remote Login<br>- Secure Credentials<br>- IP Access Controll    |

## Architecture Overview
![overview](https://github.com/qiling07/xrouter/architecture.png)

## Environment Setup
We've tested our router under different environment

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
