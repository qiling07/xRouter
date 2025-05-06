# 🔐 NAT Management Portal

This component provides a lightweight TCP-based management shell (nat>) for interacting with the NAT router and DHCP server from a remote terminal (e.g., telnet or nc).

## 📦 Features
- Remote login with salted-hash credential protection
- IP-based access control (whitelist via allowed_networks.json)
- Unified management interface for:
- NAT rules (translation table, filtering, port forwarding)
- DHCP control (lease time, static IP reservation)
- Command help menu built-in

## 🚀 Usage

1. Build the managers

```
make
```

2. Start the portal server

```
python3 portal.py
```

3. Connect to the portal (e.g., from localhost)

```
telnet localhost 8888
# or
nc localhost 8888
```

4. Example Commands

```
set <MAC_address> <lease_time>      # Set lease time for a specific MAC address
reserve <MAC_address> <IP_address>  # Reserve IP address for MAC address
print_nat                           # Show active NAT table entries
reset_nat                           # Clear all NAT mappings
filter_add <domain> <ip>           # Block a domain for a specific host IP
filter_del <domain> <ip>           # Remove a content filter rule
show_filters                        # Show all active filter rules
forward <int_ip> <int_port> <ext_port>     # Add a port forwarding rule
unforward <int_ip> <int_port> <ext_port>   # Remove a port forwarding rule
show_forwarding                     # Show all forwarding rules
portal_allow_net <network/CIDR>    # Allow login from this subnet
portal_deny_net <network/CIDR>     # Deny login from this subnet
show_portal_allowed_net            # List currently allowed networks
reset_credentials                  # Change login username/password
exit                                # Exit the management shell
```

## 🔒 Access Control
- First-time login credentials: admin / password
- Access is restricted by source IP (default: 127.0.0.1 and 10.10.1.0/24)
- Modify allowed_networks.json to add/remove IP ranges

