# Concurrent TCP Echo Server & Client

This setup includes:
- tcp-concur-echo-server.c: A multithreaded TCP echo server that handles multiple clients concurrently.
- tcp-client.c: A client that sends a sequence of bytes and checks the echoed response for correctness.

## 🛠️ Build
```bash
make
```

## 🚀 Run the Echo Server

Start the server on a specified port (e.g., 12345):

```bash
./tcp-concur-echo-server 12345
```

The server will listen for incoming TCP connections and echo back all received data.

## 🧪 Run the Client

Use the client to connect to the server and test echo behavior. For example:

```bash
./tcp-client 127.0.0.1 12345 10000
```

This sends 10,000 bytes to the server, receives the echoed data, and verifies it.
- 127.0.0.1: Server IP address
- 12345: Server port
- 10000: Number of bytes to send/verify

The client will report success if all bytes are received and verified, or print an error if mismatches occur.

## 🔄 Expected Behavior
- The client sends a message of specified length.
- The server echoes each byte back.
- The client verifies the response matches the expected sequence.
