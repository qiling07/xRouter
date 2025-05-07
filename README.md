# xRouter
Our project implements a high-performance network router combining NAT and DHCP functionalities, designed to handle real-world traffic with efficiency and flexibility. The router performs standard NAPT operations with support for port forwarding and hairpinning, while the DHCP server supports IP leasing, reservations, and lease time configuration. The architecture includes both a fast eBPF/XDP kernel module for existing NAT sessions and a user-space module for complex cases, closely mirroring the software/hardware page table model in virtual memory systems.

Additional highlights include a secure, TCP-based management portal with credential protection and IP whitelisting, per-host/domain content filtering, and full support for PMTUD and IP fragmentation. Multithreading and eBPF acceleration provide a 3× throughput improvement and 50% latency reduction compared to the baseline. The system is validated across both virtual and bare-metal environments using tools like Netperf, iPerf, and real-world streaming benchmarks, demonstrating near-native performance even with NAT enabled.

## Key Features
| Category              | Features       |
|-----------------------|---------------------------|
| **NAT**               | - PMTUD & IP Fragmentation support<br>- Port Forwarding & Hairpinning<br>- ICMP Error Message Handling<br>- Content Control<br>- Multithreading & **eBPF/XDP** optimizations               |
| **DHCP**              | - Lease Time Setting <br>- IP Reservation / Static IP        |
| **Management Portal** | - Remote Login<br>- Secure Credentials<br>- IP Access Controll    |

## Architecture Overview
![overview](https://github.com/qiling07/xrouter/blob/main/architecture.png)

Our NAT router implements standard NAPT by tracking sessions initiated by internal hosts, creating NAT bindings, and performing address/port translation for both inbound and outbound traffic. It automatically terminates idle sessions: short timeouts for connectionless protocols (UDP, ICMP), and longer ones for TCP, with a 4-minute timeout after TCP closure. 

xRouter has two components: fast_nat.c, an eBPF XDP module that handles fast-path translation for existing sessions using a “hardware” NAT table for minimal overhead; and slow_nat.c, a user-space module that handles complex cases like port forwarding, hairpinning, and ICMP error processing. It maintains a “software” NAT table and synchronizes updates to the fast path. This design mirrors the hardware/software page table split in virtual memory systems, where the fast path handles common lookups efficiently, and the slow path resolves misses and maintains consistency. To improve performance, nat slow.c uses a worker pool for parallel packet handling.

The DHCP server follows the standard DORA process: clients broadcast a DISCOVER, the server replies with an OFFER, clients send a REQUEST, and the server responds with an ACK. It maintains a lease table and supports IP reservation, renewal, and domain name assignment. Additionally, it also supports lease time adjustment and static IP assignment.

## Environment Setup
xRouter runs on Linux systems. The typical testing environment consists of one router and multiple hosts forming a local network, with the router’s external interface connected to the Internet. We provide two setup guides for testing this topology in controlled environments: one using virtual machines (VMs) and the other using CloudLab bare-metal servers. Refer to the [VM Setup Guide](https://github.com/qiling07/xrouter/blob/main/environment-setup/vm_setup.md) and [CloudLab Setup Guide](https://github.com/qiling07/xrouter/blob/main/environment-setup/cloudlab_setup.md) for detailed configuration instructions.

## How to run
- Build and run the DHCP server. Configure `dhcp/dhcp.conf` as needed. See [DHCP README](https://github.com/qiling07/xrouter/blob/main/dhcp/README.md) for more details.
  ```
  cd dhcp_server
  make
  ./dhcp_server
  ```
- Build and run the NAT server. See [NAT README](https://github.com/qiling07/xrouter/blob/main/nat/README.md) for more details.
  ```
  cd NAT_router
  make
  make config
  ./[nat_router|nat_router_ebpf] LAN_IF WAN_IF
  ```
   
## Performance
![overview](https://github.com/qiling07/xrouter/blob/main/benchmark.png)

We evaluate router performance using two tools:
- Netperf (UDP_RR): This test measures round-trip latency and throughput using fixed-size UDP packets. The command
```
netperf -H 128.105.145.222 -t UDP_RR -l 10 -- -m 64 -M 64 -P 0 -o THROUGHPUT,P50_LATENCY,P99_LATENCY,STDDEV_LATENCY
```
sends 64-byte UDP request/response pairs for 10 seconds to the target host. It reports throughput and latency statistics (median, 99th percentile, and standard deviation), which reflect how efficiently the router handles individual packets.


- iPerf (parallel TCP connections):
```
iperf -c 128.105.145.222 -P 30 | tail -n 2
```
initiates 30 concurrent TCP streams to stress test the router’s bandwidth capacity. The tail command extracts summary statistics, including total throughput. This simulates real-world high-volume TCP workloads.

- yt-dlp (YouTube download): This measure real-world application performance by downloading a YouTube video and calculating average throughput.

Our optimized NAT router achieves 3× higher throughput and reduces median latency (p50) by approximately 60% compared
to the baseline. Its performance closely matches the native case, with nearly identical latency and slightly higher
throughput. These gains arise because Netperf sends UDP packets serially, making per-packet delay critical. XDP processes packets early in the kernel, bypassing costly networking stack operations and significantly improving performance.

All configurations reach similar TCP throughput (940 Mbps), limited by the physical link speed between servers. Nonetheless, our NAT router improves short-term latency (p1 and average) because XDP reduces kernel overhead for each packet. The higher p99 jitter is likely due to CPU contention or scheduling under heavy parallel load.

When downloading large videos from Youtube, xRouter introduces no noticeable overhead in real-world streaming, **achieving throughput nearly identical to the native setup (480Mbps).**

## Known Issues
