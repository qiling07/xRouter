#!/usr/bin/env python3
import os
import json
import socket
import struct
import threading
import subprocess
from pathlib import Path

CRED_FILE = Path(__file__).parent / "credentials.json"
MANAGER_CLIENT = Path(__file__).parent / "manager_client"
LISTEN_PORT = 8888
LAN_NET     = ("10.10.1.0", "255.255.255.0")

# --- helpers ---------------------------------------------------------------

def load_creds():
    if not CRED_FILE.exists():
        creds = {"username":"admin","password":"password"}
        CRED_FILE.write_text(json.dumps(creds))
    else:
        creds = json.loads(CRED_FILE.read_text())
    return creds

def save_creds(creds):
    CRED_FILE.write_text(json.dumps(creds))

def in_lan(addr):
    ip = struct.unpack("!I", socket.inet_aton(addr))[0]
    net = struct.unpack("!I", socket.inet_aton(LAN_NET[0]))[0]
    mask= struct.unpack("!I", socket.inet_aton(LAN_NET[1]))[0]
    return (ip & mask) == (net & mask)

# --- Client handler -------------------------------------------------------

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
  passwd    # change user/password
  exit
""")
            continue

        if cmd == "passwd":
            conn.sendall(b"New username: ")
            nu = conn.recv(100).decode().strip()
            conn.sendall(b"New password: ")
            np = conn.recv(100).decode().strip()
            creds = {"username": nu, "password": np}
            save_creds(creds)
            conn.sendall(b"Credentials updated.\n")
            continue

        # invoke the existing manager_client with the entered cmd
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

# --- Server startup -------------------------------------------------------

def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # allow immediate reuse of the port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", LISTEN_PORT))
    sock.listen(5)
    print(f"NAT-portal listening on port {LISTEN_PORT}")
    try:
        while True:
            conn, addr = sock.accept()
            if not in_lan(addr[0]):
                conn.sendall(b"Access denied: not in LAN.\n")
                conn.close()
                continue
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        sock.close()

if __name__ == "__main__":
    serve()
    