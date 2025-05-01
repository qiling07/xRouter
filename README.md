## Test Pipeline
- Put the code in both the host and the server.
- Run the DHCP server
  ```
  cd dhcp_server
  make
  ./dhcp_server
  ```
- Run the NAT server
  ```
  cd NAT_router
  make
  make config
  ./nat_router INTERFACE_INT INTERFACE_EXT
  ```
- Note: `make config` depends on `iptables`. Please make sure you install it.
- Now we can test the features on the host. For example:
  - `ping google.com`
  - `nslookup youtube.com`
  - `curl google.com`
  - Feel free to use Firefox and browse any websites.
  - You may use `./manager_client print` to inspect the NAT Table.
    
## Usage
NAT router that forwards packets. Current support `ping` and UDP-based DNS query.
```bash
cd NAT_router
make
make config
./nat_router INTERFACE_INT INTERFACE_EXT
```

Router manager client.
```bash
./manager_client print

./manager_client add facebook.com 192.168.100.2

./manager_client del facebook.com 192.168.100.2

./manager_client show
```


Create a DNS query and send to `8.8.8.8`
```bash
cd ../DNS_test
make
./udp_dns_test
```

Capture all packets listened.
```bash
cd ../packet_sniffer
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
  


