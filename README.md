## Usage

NAT router that forwards packets. Current support `ping` and UDP-based DNS query.
```bash
cd NAT_router
make
./nat_router INTERFACE_INT INTERFACE_EXT
```

Create a DNS query and send to `8.8.8.8`
```bash
cd DNS_test
make
./udp_dns_test
```

HW5. Capture all packets listened.
```bash
cd packet_sniffer
make
./packet
```

## DNS test
- Put DNS_test in the host and put NAT_router in the router.
- The host connects to the internal network 1....
- The router connects to both the internal network 1 and the external network 2.
- Run `./nat_router INTERFACE_INT INTERFACE_EXT` in the router.
- Run `./udp_dns_test` on the host and check the returned packet.


## Ping test
- Put NAT_router in the router.
- The host connects to the internal network 1.
- The router connects to both the internal network 1 and the external network 2.
- Run `ping 8.8.8.8` on the host.
  


