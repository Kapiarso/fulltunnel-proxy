# FullTunnel Proxy

> A Windows system-wide Layer-3 proxy client routing OS traffic through SOCKS5 and HTTP proxies via Wintun.

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20(x64%20%7C%20ARM64)-blue?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

FullTunnel Proxy is a system-wide proxy client for Windows. It redirects operating system network traffic (TCP, UDP, and DNS) at Layer 3 using the Wintun kernel driver to an upstream SOCKS5 or HTTP/HTTPS proxy. It includes a Fake-IP DNS engine to prevent DNS leaks, a user-space network stack (gVisor Netstack), and a local web dashboard alongside a headless CLI.

---

## Key Features

- **System-Wide Routing:** Captures all network traffic across the operating system, including browsers, terminal utilities, SSH, games, and background services.
- **Proxy Protocol Support:**
  - **SOCKS5:** Unauthenticated and Username/Password authentication (RFC 1928, RFC 1929).
  - **HTTP/HTTPS CONNECT:** Basic authentication support (`Proxy-Authorization`).
- **Wintun Driver Integration:** High-throughput Layer-3 virtual TUN adapter using the official Wintun driver with minimal CPU overhead.
- **DNS Leak Protection (Fake-IP Engine):** Intercepts local port 53 DNS queries in user-space and maps domain names to a local synthetic IP pool (`198.18.0.0/15`). Domain resolution is performed remotely by the upstream proxy server.
- **UDP Relay Support:** Full UDP association support for applications and real-time protocols over proxy connections.
- **Web Dashboard & Headless CLI:** Real-time bandwidth telemetry, active socket monitoring, and public IP verification with dual interfaces.
- **Automatic Route Management:** Sets default routing paths with automatic static routes to prevent proxy loops, cleanly restoring routing tables upon shutdown.

---

## System Architecture

```
[ OS Applications (Browser, CLI, Utilities) ]
                 │
                 ▼
[ Windows Network Stack (Layer 3) ]
                 │
                 ▼ (Default Route 0.0.0.0/1 & 128.0.0.0/1)
   [ Wintun Virtual Adapter (Layer 3 TUN) ]
                 │
                 ▼
     [ gVisor Netstack (User-space TCP/IP) ]
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
 [ Fake-IP DNS Engine ]  [ Proxy Upstream Dialer ]
  (198.18.0.0/15 Pool)    (SOCKS5 / HTTP Auth)
                           │
                           ▼
                  [ Upstream Proxy Server ]
                           │
                           ▼
                      [ Internet ]
```

---

## Repository Structure

```
full_tunnel/
├── .github/
│   └── workflows/
│       └── build.yml               # GitHub Actions CI build workflow
├── cmd/
│   ├── fulltunnel/                 # Web Dashboard and GUI entrypoint
│   │   └── main.go
│   ├── cli/                        # Headless CLI entrypoint
│   │   └── main.go
│   └── speedtest/                  # Bandwidth benchmark utility
│       └── main.go
├── core/                           # Core networking engine
│   ├── config/                     # Configuration management
│   ├── dns/                        # Fake-IP DNS server implementation
│   ├── logger/                     # Structured logging
│   ├── proxy/                      # SOCKS5 and HTTP client dialers
│   ├── router/                     # Windows routing table manager
│   ├── server/                     # Local relay listener
│   ├── stack/                      # User-space TCP/IP stack (gVisor)
│   ├── stats/                      # Bandwidth tracking and metrics
│   ├── tun/                        # Layer-3 Wintun driver interface
│   ├── admin_windows.go            # Windows administrator privileges helper
│   └── engine.go                   # Core lifecycle coordinator
├── docs/                           # Documentation
│   ├── ARCHITECTURE_FLOW.md        # Packet pipeline and sequence diagrams
│   └── PRD.md                      # Product requirements document
├── scripts/                        # Utility scripts
│   ├── build.bat                   # Build script for Windows
│   └── toten.bat                   # Emergency route reset script
├── web/                            # Embedded Web Dashboard
│   ├── dashboard.html              # Frontend user interface
│   ├── html.go                     # Static asset embedding
│   └── server.go                   # HTTP API and WebSocket handlers
├── wintun_sdk/                     # Wintun driver headers and documentation
├── .gitattributes                  # Git line-ending configuration
├── .gitignore                      # Git ignore rules
├── go.mod                          # Go module dependencies
├── go.sum                          # Go module checksums
├── LICENSE                         # MIT License
├── Makefile                        # Build targets
├── main.go                         # Default project entrypoint
└── README.md                       # Main documentation
```

---

## Getting Started

> [!IMPORTANT]
> Must be run with **Administrator privileges** to register the Wintun adapter and configure the Windows routing table.

### 1. Running Directly from Source
Open PowerShell or Command Prompt as Administrator:
```powershell
# Run the Web Dashboard:
go run .

# Or run the Headless CLI:
go run ./cmd/cli -host 127.0.0.1 -port 1080 -type socks5
```

### 2. Compiling Executables
```bash
# Build the Web Dashboard (produces fulltunnel.exe):
go build -ldflags "-s -w" -o fulltunnel.exe main.go

# Build the Headless CLI (produces fulltunnel-cli.exe):
go build -ldflags "-s -w" -o fulltunnel-cli.exe ./cmd/cli/main.go
```
*(Alternatively, use `scripts\build.bat`)*

### 3. Running the Web Dashboard Binary
Right-click `fulltunnel.exe` and select **Run as Administrator**, or run from an elevated terminal:
```powershell
.\fulltunnel.exe
```
The browser will automatically open the dashboard at `http://127.0.0.1:28888`.

#### Command-line Options:
- `.\fulltunnel.exe --headless` (Starts without opening the default browser)
- `.\fulltunnel.exe --connect` (Automatically activates the tunnel on startup)
- `.\fulltunnel.exe --port 30000` (Specifies a custom dashboard port)

---

### 4. Running the Headless CLI Binary
Run from an elevated Command Prompt or PowerShell:
```powershell
.\fulltunnel-cli.exe -host 203.0.113.50 -port 1080 -type socks5 -user myuser -pass mypassword
```

#### CLI Parameters:
- `-host`: Target proxy server IP or hostname (Required)
- `-port`: Proxy port (Default: `1080`)
- `-type`: Proxy protocol (`socks5`, `http`, `https`)
- `-user`: Authentication username (Optional)
- `-pass`: Authentication password (Optional)

---

## Configuration (`config.json`)

Configuration is saved automatically to:
`%USERPROFILE%\AppData\Roaming\FullTunnel\config.json`

Example configuration:
```json
{
  "active_profile_id": "prof-1",
  "profiles": [
    {
      "id": "prof-1",
      "name": "Default Proxy",
      "type": "socks5",
      "host": "proxy.example.com",
      "port": 10808,
      "username": "user",
      "password": "secret_password",
      "enable_udp": true,
      "dns_mode": "fakeip",
      "bypass_lan": true
    }
  ],
  "tun_name": "FullTunnel",
  "tun_ip": "172.19.0.1",
  "tun_mask": "255.255.255.252",
  "tun_gateway": "172.19.0.2",
  "dns_address": "172.19.0.2:53",
  "fake_ip_pool": "198.18.0.0/15",
  "mtu": 1500,
  "http_port": 28888,
  "auto_start": false,
  "kill_switch": true
}
```

---

## License

This project is licensed under the [MIT License](LICENSE).
