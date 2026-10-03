# FullTunnel Enterprise 🛡️
> **Enterprise-Grade Windows Full-Tunnel Proxy Connector**

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20(x64%20%7C%20ARM64)-blue?style=flat-square&logo=windows)](https://microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

**FullTunnel Enterprise** adalah aplikasi konektor proxy full-tunnel untuk Windows yang mengalihkan **100% trafik OS** (TCP, UDP, ICMP, DNS) pada network layer (Layer 3) melalui driver kernel **Wintun** ke upstream proxy (SOCKS5 / HTTP CONNECT). Dilengkapi sistem **Fake-IP Zero-Leak DNS**, userspace TCP/IP stack (**gVisor Netstack**), dan antarmuka **Modern Web Dashboard**.

---

## 🌟 Fitur Utama

- 🛡️ **100% System-Wide Coverage:** Menangkap seluruh trafik jaringan sistem operasi (Browser, Game, Terminal, SSH, Docker, Git, Python, Node.js).
- 🔑 **Full Upstream Authentication:**
  - **SOCKS5:** No-Auth (`0x00`) & Username/Password Authentication (`0x02` - RFC 1929).
  - **HTTP/HTTPS CONNECT:** Basic Authentication (`Proxy-Authorization: Basic`).
- ⚡ **Driver Kernel C Wintun:** Throughput multi-gigabit dengan ring buffer 4MB dan CPU overhead < 1%.
- 🌐 **Zero DNS Leak (Fake-IP Engine):** Menjawab query DNS lokal dari pool `198.18.0.0/15` dalam 0ms tanpa mengirim DNS query mentah ke ISP lokal.
- 🎮 **Dukungan Penuh UDP:** UDP Associate penuh untuk game, VoIP, dan komunikasi real-time melalui proxy.
- 📊 **Real-time Live Telemetry:** Web dashboard dengan grafik throughput (Upload/Download), monitor socket aktif, dan verifikasi IP publik instan.
- 🔁 **Auto Loop-Prevention & Safe Rollback:** Otomatis menambahkan static route untuk IP Proxy upstream agar tidak terjadi routing loop, dan merestorasi tabel routing Windows secara aman saat ditutup.

---

## 🏗️ Arsitektur Sistem

```
[ OS Applications (Browser, CLI, Game) ]
                 │
                 ▼
[ Windows Network Stack (Layer 3) ]
                 │
                 ▼ (Default Route 0.0.0.0/1 & 128.0.0.0/1)
   [ Wintun Virtual Adapter (Layer 3 TUN) ]
                 │
                 ▼
     [ gVisor Netstack (Userspace TCP/IP) ]
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
 [ Fake-IP DNS Engine ]  [ Proxy Upstream Dialer ]
  (Zero Leak 198.18/15)   (SOCKS5 / HTTP Auth)
                           │
                           ▼
                  [ Upstream Proxy Server ]
                           │
                           ▼
                      [ Internet ]
```

---

## 📁 Struktur Direktori Repository

```
full_tunnel/
├── .github/
│   └── workflows/
│       └── build.yml               # GitHub Actions CI automated build
├── cmd/
│   ├── fulltunnel/                 # GUI & Web Dashboard entrypoint
│   │   └── main.go
│   ├── cli/                        # Headless CLI entrypoint
│   │   └── main.go
│   └── speedtest/                  # Speed benchmark CLI tool
│       └── main.go
├── core/                           # Core networking engine
│   ├── config/                     # Configuration management & JSON parsing
│   ├── dns/                        # Fake-IP Zero-Leak DNS server
│   ├── logger/                     # Structured logging
│   ├── proxy/                      # SOCKS5 (RFC 1928/1929) & HTTP dialers
│   ├── router/                     # Windows routing table manager
│   ├── server/                     # Local SOCKS5 listener relay
│   ├── stack/                      # Userspace TCP/IP stack (gVisor)
│   ├── stats/                      # Telemetry & bandwidth tracker
│   ├── tun/                        # Layer-3 Wintun driver & embedded DLLs
│   ├── admin_windows.go            # Windows UAC admin permission checker
│   └── engine.go                   # Orchestrator
├── docs/                           # Dokumentasi teknis
│   ├── ARCHITECTURE_FLOW.md        # Diagram detail alur paket & packet pipeline
│   └── PRD.md                      # Product Requirements Document
├── scripts/                        # Script otomasi Windows
│   ├── build.bat                   # 1-Click build script untuk Windows
│   └── toten.bat                   # Emergency stop & reset route script
├── web/                            # Embedded Web Dashboard
│   ├── dashboard.html              # Modern glassmorphism UI
│   ├── html.go                     # Embedded HTML assets
│   └── server.go                   # REST API & WebSocket handlers
├── wintun_sdk/                     # Official signed Wintun drivers (x86, amd64, ARM64)
├── .gitattributes                  # Git line endings & binary flags
├── .gitignore                      # Git ignore rules
├── go.mod                          # Go module dependencies
├── go.sum                          # Module checksums
├── LICENSE                         # MIT License
├── Makefile                        # Build targets
├── main.go                         # Root entrypoint
└── README.md                       # Dokumentasi utama
```

---

## 🚀 Cara Menjalankan

> [!IMPORTANT]
> **Wajib dijalankan sebagai Administrator** (Run as Administrator) karena program perlu mendaftarkan virtual adapter Wintun dan mengatur Windows Routing Table.

### 1. Langsung Jalankan (Tanpa Build Executable)
Buka PowerShell (Run as Administrator):
```powershell
# Jalankan GUI / Web Dashboard langsung:
go run .

# Atau jalankan Headless CLI langsung:
go run ./cmd/cli 127.0.0.1:1080
```

### 2. Kompilasi Manual dengan `go build`
```bash
# GUI / Web Dashboard (menghasilkan fulltunnel.exe)
go build -ldflags "-s -w" -o fulltunnel.exe main.go

# Headless CLI (menghasilkan fulltunnel-cli.exe)
go build -ldflags "-s -w" -o fulltunnel-cli.exe ./cmd/cli/main.go
```
*(Atau kamu juga bisa gunakan script otomasi `scripts\build.bat`)*

### 3. Menjalankan Binary GUI / Web Dashboard
Klik kanan `fulltunnel.exe` -> **Run as Administrator**, atau jalankan lewat PowerShell:
```powershell
.\fulltunnel.exe
```
Browser akan otomatis terbuka menampilkan dashboard di `http://127.0.0.1:28888`.

#### Opsi Command Line:
- `.\fulltunnel.exe --headless` (Jalankan tanpa otomatis membuka browser)
- `.\fulltunnel.exe --connect` (Otomatis langsung mengaktifkan tunnel saat start)
- `.\fulltunnel.exe --port 30000` (Ganti port web dashboard)

---

### 4. Menjalankan Binary Headless CLI
Jalankan langsung melalui PowerShell / Command Prompt (Admin):
```powershell
.\fulltunnel-cli.exe -host 203.0.113.50 -port 1080 -type socks5 -user myuser -pass mysecretpassword
```

#### Argumen CLI:
- `-host`: IP Address atau Domain Server Proxy (Wajib)
- `-port`: Port Server Proxy (Default: `1080`)
- `-type`: Protokol (`socks5`, `http`, `https`)
- `-user`: Username autentikasi (Opsional)
- `-pass`: Password autentikasi (Opsional)

---

## 📂 Struktur Konfigurasi (`config.json`)

Konfigurasi disimpan secara otomatis di:
`%USERPROFILE%\AppData\Roaming\FullTunnel\config.json`

Contoh isi konfigurasi:
```json
{
  "active_profile_id": "prof-1",
  "profiles": [
    {
      "id": "prof-1",
      "name": "Corporate SOCKS5",
      "type": "socks5",
      "host": "proxy.example.com",
      "port": 10808,
      "username": "corporate_user",
      "password": "secret_password_123",
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

## 📤 Cara Push ke GitHub

Ikuti langkah-langkah berikut untuk mengunggah repositori ini ke GitHub:

```bash
# 1. Buka folder full_tunnel di terminal
cd "C:\Users\Kapiarso\Desktop\Project_Porto\full_tunnel"

# 2. Hubungkan dengan remote repository GitHub kamu
git remote add origin https://github.com/<USERNAME-KAMU>/<NAMA-REPO-KAMU>.git

# 3. Push ke GitHub
git push -u origin main
```

---

## 📜 Lisensi

Proyek ini dilisensikan di bawah [MIT License](LICENSE).
