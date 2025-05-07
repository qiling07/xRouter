# CloudLab setup guides
## CloudLab machines preparation
Use `cloudlab-router-profile.py` to create servers of the following topology.

<!-- ![CloudLab Topology](https://github.com/qiling07/xrouter/blob/main/environment-setup/cloudlab_topology.png) -->
<img src="https://github.com/qiling07/xrouter/blob/main/environment-setup/cloudlab_topology.png" width="300"/>

In this topology, node0, node1, and node2 form a local network, where node2 acts as the gateway (router). Node3 connects to node2 from outside the LAN, simulating a remote server. This setup enables simple and controlled performance testing of the router.

## Network configuration
### Network Configuration for Hosts
Set the default gateway to the router's LAN IP so that all outbound traffic is routed through the router. After setting this route, the host will no longer be reachable directly from the outside. You will only be able to SSH into the host via the router.

```bash
sudo ip route add default via $ROUTER_LAN_IP dev $LAN_IF
```

Replace $ROUTER_LAN_IP with the actual LAN IP address of the router (e.g., 192.168.20.1), and $LAN_IF with the name of your host’s LAN interface (e.g., enp6s0f0).

