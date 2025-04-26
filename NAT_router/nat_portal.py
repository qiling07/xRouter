#!/usr/bin/env python3
import os
import json
import socket
import struct
import threading
import subprocess
import ipaddress
from pathlib import Path

CRED_FILE        = Path(__file__).parent / "credentials.json"
ALLOWED_FILE     = Path(__file__).parent / "allowed_networks.json"
MANAGER_CLIENT   = Path(__file__).parent / "manager_client"
LISTEN_PORT      = 8888

# ——— Persistence for allowed networks ———

def load_allowed_networks():
    if not ALLOWED_FILE.exists():
        # default to your LAN
        defaults = ["10.10.1.0/24"]
        ALLOWED_FILE.write_text(json.dumps(defaults))
        return [ipaddress.IPv4Network(cidr) for cidr in defaults]
    lst = json.loads(ALLOWED_FILE.read_text())
    return [ipaddress.IPv4Network(cidr) for cidr in lst]

def save_allowed_networks(nets):
    # nets: List[ipaddress.IPv4Network]
    cidrs = [str(net) for net in nets]
    ALLOWED_FILE.write_text(json.dumps(cidrs))

# load once at startup
ALLOWED_NETWORKS = load_allowed_networks()

# ——— Helpers ———

def get_local_ips():
    """All IPv4 addresses on this box (always allowed)."""
    ips = {ipaddress.IPv4Address("127.0.0.1")}
    for fam, *_ , sockaddr in socket.getaddrinfo(socket.gethostname(), None):
        if fam == socket.AF_INET:
            ips.add(ipaddress.IPv4Address(sockaddr[0]))
    return ips

def is_allowed(addr_str):
    addr = ipaddress.IPv4Address(addr_str)
    # router’s own IPs
    if addr in get_local_ips():
        return True
    # any configured network
    return any(addr in net for net in ALLOWED_NETWORKS)

# ——— Core server/handler ———

def load_creds():
    if not CRED_FILE.exists():
        creds = {"username": "admin", "password": "password"}
        CRED_FILE.write_text(json.dumps(creds))
    else:
        creds = json.loads(CRED_FILE.read_text())
    return creds

def save_creds(creds):
    CRED_FILE.write_text(json.dumps(creds))

def handle_client(conn, addr):
    creds = load_creds()
    conn.sendall(b"Username: ")
    user = conn.recv(100).decode().strip()
    conn.sendall(b"Password: ")
    pwd  = conn.recv(100).decode().strip()
    if user != creds["username"] or pwd != creds["password"]:
        conn.sendall(b"Invalid credentials. Goodbye.\n")
        conn.close()
        return

    conn.sendall(b"Welcome to NAT-portal. Type 'help' for commands.\n")
    while True:
        conn.sendall(b"nat> ")
        data = conn.recv(256)
        if not data:
            break
        cmd = data.decode().strip()

        if cmd in ("exit", "quit"):
            break

        if cmd == "help":
            conn.sendall(b"""\
Commands:
  print
  reset
  add <domain>
  del <domain>
  show
  forward <internal_ip> <internal_port> <external_port>
  unforward <internal_ip> <internal_port> <external_port>
  show_forwarding
  latency
  allow  <network/CIDR>
  deny   <network/CIDR>
  show_allowed
  passwd
  exit
""")
            continue

        # ——— allow <network/CIDR>
        if cmd.startswith("allow "):
            try:
                _, cidr = cmd.split(None, 1)
                new_net = ipaddress.IPv4Network(cidr, strict=False)
            except Exception:
                conn.sendall(b"Usage: allow <network/CIDR>\n")
                continue

            # merge with existing
            merged = list(ipaddress.collapse_addresses(ALLOWED_NETWORKS + [new_net]))
            ALLOWED_NETWORKS.clear()
            ALLOWED_NETWORKS.extend(merged)
            save_allowed_networks(ALLOWED_NETWORKS)
            conn.sendall(f"Allowed {new_net}\n".encode())
            continue

        # ——— deny <network/CIDR>
        if cmd.startswith("deny "):
            try:
                _, cidr = cmd.split(None, 1)
                deny_net = ipaddress.IPv4Network(cidr, strict=False)
            except Exception:
                conn.sendall(b"Usage: deny <network/CIDR>\n")
                continue

            survivors = []
            for net in ALLOWED_NETWORKS:
                if net.overlaps(deny_net):
                    # subtract deny_net from net
                    survivors.extend(net.address_exclude(deny_net))
                else:
                    survivors.append(net)
            # collapse in case of adjacency
            ALLOWED_NETWORKS.clear()
            ALLOWED_NETWORKS.extend(ipaddress.collapse_addresses(survivors))
            save_allowed_networks(ALLOWED_NETWORKS)
            conn.sendall(f"Denied {deny_net}\n".encode())
            continue

        # ——— show_allowed
        if cmd == "show_allowed":
            conn.sendall(b"Allowed networks:\n")
            for net in ALLOWED_NETWORKS:
                conn.sendall(f"  {net}\n".encode())
            conn.sendall(b"Router IPs (always allowed):\n")
            for ip in get_local_ips():
                conn.sendall(f"  {ip}\n".encode())
            continue

        if cmd == "passwd":
            conn.sendall(b"New username: ")
            nu = conn.recv(100).decode().strip()
            conn.sendall(b"New password: ")
            np = conn.recv(100).decode().strip()
            save_creds({"username": nu, "password": np})
            conn.sendall(b"Credentials updated.\n")
            continue

        # pass-thru for all other commands
        try:
            proc = subprocess.run(
                [str(MANAGER_CLIENT)] + cmd.split(),
                cwd=MANAGER_CLIENT.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5.0
            )
            output = proc.stdout
        except Exception as e:
            output = f"Error running manager_client: {e}\n"
        conn.sendall(output.encode())

    conn.close()

def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", LISTEN_PORT))
    sock.listen(5)
    print(f"NAT-portal listening on port {LISTEN_PORT}")
    try:
        while True:
            conn, addr = sock.accept()
            if not is_allowed(addr[0]):
                conn.sendall(b"Access denied: your IP is not allowed.\n")
                conn.close()
                continue
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        sock.close()

if __name__ == "__main__":
    serve()