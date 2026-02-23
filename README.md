# Professional C HTTP/WebSocket Server

A high-performance, edge-triggered I/O multiplexing HTTPS and WebSocket server built from scratch in C using `epoll`. This project implements modern web standards including TLS/SSL, JWT authentication, and real-time communication.

---

## 🚀 Key Features

- **High-Performance Architecture**: Core event loop powered by `epoll` (Edge-Triggered) for efficient handling of thousands of concurrent connections without the overhead of multi-threading.
- **Secure Communication**: Full TLS/SSL support via OpenSSL, providing encrypted HTTPS and WebSocket (WSS) layers.
- **Real-Time WebSockets**: Integrated WebSocket server (RFC 6455) for low-latency, bidirectional communication.
- **State-of-the-Art Auth**: Secure JWT (JSON Web Token) authentication for stateless, scalable session management.
- **Persistent Storage**: Integrated with SQLite3 for reliable data management.
- **Safety & Robustness**:
  - Graceful shutdown/cleanup on SIGINT (Ctrl+C).
  - Rate limiting to prevent abuse.
  - Connection limits (global and per-IP).
  - Timeout tracking for slow/stale clients.
- **Structured Logging**: Thread-safe, multi-level logging system.

---

## 🛠 Tech Stack

- **Language**: C
- **I/O Engine**: Linux `epoll`
- **Networking**: BSD Sockets, OpenSSL
- **Database**: SQLite3
- **Authentication**: JWT (JSON Web Tokens)
- **Serialization**: cJSON

---

## 📋 Prerequisites

Ensure you have the following libraries installed on your Linux system:

```bash
# Ubuntu/Debian example
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libsqlite3-dev libcjson-dev libjwt-dev
```

---

## ⚙️ Configuration & Setup

### 1. SSL Certificates
The server requires SSL certificates for HTTPS/WSS. Generate self-signed certificates for local development:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```

### 2. Environment Variables
For security, the JWT secret key must be stored explicitly in your environment. **Never hardcode this key.**

```bash
# Generate a secure key
export SECRET_KEY=$(openssl rand -base64 32)
```

> [!IMPORTANT]
> You must `export SECRET_KEY` in every new terminal session before running the server, or add it to your `.bashrc` / `.env`.

### 3. Server Configuration
Edit `server.conf` to adjust port, timeouts, and limits:
- `port`: Default 8443
- `max_connections`: Global limit
- `db_path`: Path to SQLite database

---

## 🏗 Build & Run

### Compile the Server
```bash
make
```

### Run the Server
```bash
make run
```

### Clean Build Files
```bash
make clean
```

---

## 📂 Project Structure

- `src/` - Core implementation (`server.c`, `auth.c`, `websocket.c`, etc.)
- `include/` - Header files and API definitions
- `public/` - Static assets and frontend templates
- `certs/` - (Required) Your SSL certificates
- `server.conf` - Main configuration file
- `users.db` - SQLite database (auto-created on first run)

---

## 📜 API Highlights

- **Auth**: `POST /register`, `POST /login`
- **User management**: `GET /me`, `PUT /me` (Requires JWT)
- **Chat**: Connect via WebSocket at `/ws` (Requires JWT protocol negotiation)

---

## ⚖️ License
Copyright (c) 2026. All rights reserved.
