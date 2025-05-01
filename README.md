## Basic Test Pipeline
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
  - On the server, you may use `./manager_client print` to inspect the NAT Table.
   
