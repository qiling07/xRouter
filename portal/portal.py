#!/usr/bin/env python3
import os
import json
import socket
import struct
import threading
import subprocess
import ipaddress
import hashlib
import base64
from pathlib import Path

CRED_FILE        = Path(__file__).parent / "credentials.json"
ALLOWED_FILE     = Path(__file__).parent / "allowed_networks.json"
MANAGER_CLIENT   = Path(__file__).parent / "nat_manager"
DHCP_MANAGER     = Path(__file__).parent / "dhcp_manager"
LISTEN_PORT      = 8888

# ——— Persistence for allowed networks ———

def load_allowed_networks():
    if not ALLOWED_FILE.exists():
        defaults = ["10.10.1.0/24"]
        ALLOWED_FILE.write_text(json.dumps(defaults))
        return [ipaddress.IPv4Network(c) for c in defaults]
    lst = json.loads(ALLOWED_FILE.read_text())
    return [ipaddress.IPv4Network(c) for c in lst]

def save_allowed_networks(nets):
    cidrs = [str(net) for net in nets]
    ALLOWED_FILE.write_text(json.dumps(cidrs))

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
    if addr in get_local_ips():
        return True
    return any(addr in net for net in ALLOWED_NETWORKS)

# ——— Credential handling ———

def load_creds():
    if not CRED_FILE.exists():
        # first-run defaults
        salt = os.urandom(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', b"password", salt, 100_000)
        creds = {
            "username":      "admin",
            "salt":          base64.b64encode(salt).decode(),
            "password_hash": base64.b64encode(pwd_hash).decode()
        }
        CRED_FILE.write_text(json.dumps(creds))
    else:
        creds = json.loads(CRED_FILE.read_text())
    return creds

def save_creds(creds_plain):
    # creds_plain: {"username": <str>, "password": <str>}
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        creds_plain['password'].encode(),
        salt,
        100_000
    )
    stored = {
        "username":      creds_plain['username'],
        "salt":          base64.b64encode(salt).decode(),
        "password_hash": base64.b64encode(pwd_hash).decode()
    }
    CRED_FILE.write_text(json.dumps(stored))

# ——— Core server/handler ———

def handle_client(conn, addr):
    creds = load_creds()
    conn.sendall(b"Username: ")
    user = conn.recv(100).decode().strip()
    conn.sendall(b"Password: ")
    pwd  = conn.recv(100).decode().strip()

    # verify
    salt = base64.b64decode(creds['salt'])
    expected_hash = base64.b64decode(creds['password_hash'])
    test_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 100_000)

    if user != creds["username"] or test_hash != expected_hash:
        conn.sendall(b"Invalid credentials. Goodbye.\n")
        conn.close()
        return

    conn.sendall(b"Welcome to NAT Management Portal. Type 'help' for commands.\n")
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
  set <MAC_address> <lease_time>      Set lease time for a specific MAC address
  reserve <MAC_address> <IP_address>  Reserve IP_address for MAC_address
  print_nat
  reset_nat
  filter_add <domain> <ip>
  filter_del <domain> <ip>
  show_filters
  forward <int_ip> <int_port> <ext_port>
  unforward <int_ip> <int_port> <ext_port>
  show_forwarding
  portal_allow_net        <network/CIDR>
  portal_deny_net         <network/CIDR>
  show_portal_allowed_net
  reset_credentials
  exit
""")
            continue

        if cmd.startswith("portal_allow_net "):
            try:
                _, cidr = cmd.split(None, 1)
                new_net = ipaddress.IPv4Network(cidr, strict=False)
            except:
                conn.sendall(b"Usage: portal_allow_net <network/CIDR>\n") 
                continue
            merged = list(ipaddress.collapse_addresses(ALLOWED_NETWORKS + [new_net]))
            ALLOWED_NETWORKS.clear()
            ALLOWED_NETWORKS.extend(merged)
            save_allowed_networks(ALLOWED_NETWORKS)
            conn.sendall(f"Allowed {new_net}\n".encode())
            continue

        if cmd.startswith("portal_deny_net "):
            try:
                _, cidr = cmd.split(None, 1)
                deny_net = ipaddress.IPv4Network(cidr, strict=False)
            except:
                conn.sendall(b"Usage: portal_deny_net <network/CIDR>\n")
                continue
            survivors = []
            for net in ALLOWED_NETWORKS:
                if net.overlaps(deny_net):
                    survivors.extend(net.address_exclude(deny_net))
                else:
                    survivors.append(net)
            ALLOWED_NETWORKS.clear()
            ALLOWED_NETWORKS.extend(ipaddress.collapse_addresses(survivors))
            save_allowed_networks(ALLOWED_NETWORKS)
            conn.sendall(f"Denied {deny_net}\n".encode())
            continue

        if cmd == "show_portal_allowed_net":
            conn.sendall(b"Allowed networks:\n")
            for net in ALLOWED_NETWORKS:
                conn.sendall(f"  {net}\n".encode())
            conn.sendall(b"Router IPs (always allowed):\n")
            for ip in get_local_ips():
                conn.sendall(f"  {ip}\n".encode())
            continue

        if cmd == "reset_credentials":
            conn.sendall(b"New username: ")
            nu = conn.recv(100).decode().strip()
            conn.sendall(b"New password: ")
            np = conn.recv(100).decode().strip()
            save_creds({"username": nu, "password": np})
            conn.sendall(b"Credentials updated.\n")
            continue
        
        if cmd.startswith("set ") or cmd.startswith("reserve "):
            try:
                proc = subprocess.run(
                    [str(DHCP_MANAGER)] + cmd.split(),
                    cwd=DHCP_MANAGER.parent,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=5.0
                )
                output = proc.stdout
            except Exception as e:
                output = f"Error running DHCP_MANAGER: {e}\n"
            conn.sendall(output.encode())
            
        # fallback to manager_client
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
            output = f"Error running NAT_MANAGER: {e}\n"
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
    