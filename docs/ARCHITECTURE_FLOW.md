# ARSITEKTUR TEKNIS & ALUR SISTEM
## Enterprise Windows Full-Tunnel Proxy Connector

Dokumen ini menjelaskan rancangan arsitektur tingkat tinggi (High-Level Architecture), alur paket data (Packet Flow), manajemen routing Windows, mekanisme autentikasi, serta pilihan Tech Stack terbaik.

---

## 1. Rekomendasi Tech Stack (Enterprise High-Performance)

Untuk membangun aplikasi konektor jaringan setingkat enterprise di Windows dengan performa maksimal, latensi terendah, dan konsumsi memori minimal, berikut adalah stack yang direkomendasikan:

| Layer | Rekomendasi Teknologi | Alasan & Keunggulan |
| :--- | :--- | :--- |
| **Core Network Engine** | **Go (Golang 1.22+)** *(dengan Wintun C bindings + gVisor/netstack)* | - Standar industri networking proxy modern (dipakai Sing-box, Mihomo, Cloudflare).<br>- Zero-memory-leak, concurrency goroutine sangat cepat untuk ribuan TCP/UDP streams simultan.<br>- Ekosistem protokol proxy terlengkap (SOCKS5 Auth, HTTP CONNECT, Shadowsocks, Fake-IP DNS). |
| **Virtual Network Driver** | **Wintun (Layer 3 TUN Driver by WireGuard team)** | - Driver C kernel native Windows dengan zero-copy ring buffers.<br>- Jauh lebih cepat dan stabil dibanding TAP-Windows lama (OpenVPN TAP).<br>- Throughput gigabit dengan CPU overhead < 1%. |
| **TCP/IP Stack** | **gVisor Netstack (Google)** atau **LwIP Optimized** | - Menerjemahkan raw IP packets L3 dari adapter TUN menjadi TCP streams & UDP datagrams di user space.<br>- Keamanan tingkat tinggi (memory safe sandbox). |
| **Desktop GUI / Client** | **Wails v2 (Go + TypeScript / React)** atau **Tauri (Rust/React)** | - Menghasilkan **Single Binary .exe** mandiri (sangat ringan ~15-25MB vs Electron yang >120MB).<br>- Menggunakan Windows WebView2 (Edge Chromium native Windows), performa render 60 FPS.<br>- Komunikasi IPC antara UI dan Core Engine berjalan langsung di memori tanpa overhead HTTP/WebSocket lokal yang lambat. |
| **Security & Routing** | **Win32 IP Helper API (`iphlpapi.dll`) + Windows Filtering Platform (WFP)** | - Manipulasi route table Windows secara programatik instan.<br>- Perlindungan Kill-Switch level kernel. |

---

## 2. Diagram Arsitektur Sistem

```
+-----------------------------------------------------------------------------------+
|                            WINDOWS USER SPACE                                     |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |             GUI / Dashboard (Wails v2 + React/TypeScript UI)                |  |
|  |  - Real-time Traffic Graph   - Profile Manager (SOCKS5/HTTP Auth)           |  |
|  |  - Active Connection Monitor - Split-tunneling Rules & DNS Settings          |  |
|  +--------------------------------------+--------------------------------------+  |
|                                         | IPC (In-Memory Go Bindings)             |
|  +--------------------------------------v--------------------------------------+  |
|  |                  SECURETUNNEL CORE ENGINE (Golang Daemon)                   |  |
|  |                                                                             |  |
|  |  +-----------------------+  +--------------------+  +--------------------+  |  |
|  |  |    Fake-IP / Smart    |  | Rule & Route Engine|  |  Upstream Client   |  |  |
|  |  |      DNS Engine       |  | (Bypass LAN / Kill)|  |  (SOCKS5 / HTTP)   |  |  |
|  |  | (198.18.0.0/15 Pool)  |  |                    |  | (RFC 1929 Auth)    |  |  |
|  |  +-----------+-----------+  +---------+----------+  +---------+----------+  |  |
|  |              |                        |                       |             |  |
|  |  +-----------v------------------------v-----------------------v----------+  |  |
|  |  |                gVisor Netstack (Userspace TCP/IP Stack)               |  |  |
|  |  |   - IP Packet Reassembly      - TCP Stream Handler (Mux)              |  |  |
|  |  |   - NAT / Connection State    - UDP Associate Buffer                  |  |  |
|  |  +-----------------------------------+-----------------------------------+  |  |
|  +--------------------------------------^--------------------------------------+  |
+-----------------------------------------|-----------------------------------------+
|                            WINDOWS KERNEL SPACE                                   |
|                                         | Wintun Ring Buffer                      |
|  +--------------------------------------v--------------------------------------+  |
|  |                      WINTUN VIRTUAL NETWORK ADAPTER                         |  |
|  |                     (Layer 3 Virtual NIC: 172.19.0.1/30)                    |  |
|  +--------------------------------------^--------------------------------------+  |
|                                         | Default Route (0.0.0.0/1 & 128.0.0.0/1) |
|  +--------------------------------------|--------------------------------------+  |
|  |                     WINDOWS TCP/IP STACK & ROUTING                          |  |
|  |               (Semua Aplikasi: Browser, Game, CMD, Docker, dll.)            |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------|-----------------------------------------+
                                          | Outbound to Proxy Server
                                          v
                              +-----------------------+
                              |   Physical Network    |
                              | (Wi-Fi / Ethernet NIC)|
                              +-----------+-----------+
                                          |
                                          | Encrypted/Authenticated SOCKS5/HTTP
                                          v
                              +-----------------------+
                              | Upstream Proxy Server |
                              | (Auth: User & Pass)   |
                              +-----------+-----------+
                                          |
                                          v
                                   INTERNET ACCESS
```

---

## 3. Alur Kerja & Siklus Hidup Paket Data (Data Flow)

### 3.1 Alur Inisiasi Koneksi & Routing Setup (Saat "Connect" Ditekan)
1. **Wintun Adapter Setup:** Core Engine menginstansiasi adapter TUN virtual `SecureTunnel-Wintun` dengan IP lokal (misal: `172.19.0.1/30`).
2. **Proxy Endpoint Route Exclusion:**
   - IP Address Server Proxy (misal: `203.0.113.50`) ditambahkan ke Routing Table dengan gateway adapter fisik asli.
   - *Tujuan:* Mencegah *Routing Loop* (agar paket yang dikirim Core Engine ke Proxy tidak tertangkap lagi oleh Wintun adapter).
3. **Full-Tunnel Routing Overrides:**
   - Menambahkan route `0.0.0.0/1` dan `128.0.0.0/1` mengarah ke Wintun adapter (`172.19.0.2`).
   - Teknik ini menutupi seluruh ruang IPv4 `0.0.0.0/0` tanpa menghapus default gateway asli Windows. Jika aplikasi dimatikan, routing kembali normal secara instan.
4. **DNS Interception:** Menetapkan DNS Server pada Wintun ke `172.19.0.2` (Local Fake-IP DNS Engine).

---

### 3.2 Alur Pemrosesan Trafik TCP/UDP (Packet Pipeline)

```
[Aplikasi Windows: e.g. curl/game/browser]
       |
       | 1. Kirim DNS Request (contoh: target.com)
       v
[Fake-IP DNS Engine (172.19.0.2)]
       |
       | 2. Catat mapping: 198.18.0.15 <-> target.com
       |    Balas langsung DNS A Record: 198.18.0.15 (0ms latency!)
       v
[Aplikasi Windows]
       |
       | 3. Buat koneksi TCP ke 198.18.0.15:443
       v
[Wintun Adapter (Kernel)]
       |
       | 4. Tangkap Raw IP Packet melalui Ring Buffer
       v
[gVisor Netstack (Core Engine)]
       |
       | 5. Terjemahkan paket IP -> TCP Stream
       |    Lookup Fake-IP: 198.18.0.15 -> Domain target.com:443
       v
[SOCKS5 / HTTP Connector Client]
       |
       | 6. SOCKS5 Handshake dengan Upstream Proxy Server:
       |    - Auth RFC 1929: [0x01, UserLen, User, PassLen, Pass] -> [0x01, 0x00 (Success)]
       |    - Connect Request: CMD=0x01, ATYP=0x03 (Domain), "target.com", Port=443
       v
[Upstream Proxy Server]
       |
       | 7. Teruskan stream ke target.com di internet
       v
[Internet / Target Server]
```

---

### 3.3 Alur Autentikasi SOCKS5 (RFC 1928 / 1929)

```
Core Engine Client                                    Upstream SOCKS5 Proxy Server
       |                                                            |
       |  1. Method Negotiation: [0x05, 0x01, 0x02 (Username/Pass)] |
       |----------------------------------------------------------->|
       |                                                            |
       |  2. Server Response: [0x05, 0x02 (Accepted Auth Required)] |
       |<-----------------------------------------------------------|
       |                                                            |
       |  3. RFC 1929 Auth: [0x01, len(user), user, len(pass), pass]|
       |----------------------------------------------------------->|
       |                                                            |
       |  4. Auth Status: [0x01, 0x00 (Success)]                    |
       |<-----------------------------------------------------------|
       |                                                            |
       |  5. Connect Request (Target Host/Port):                    |
       |     [0x05, 0x01 (CONNECT), 0x00, 0x03 (Domain), ...]       |
       |----------------------------------------------------------->|
       |                                                            |
       |  6. Connect Success: [0x05, 0x00, 0x00, ...]               |
       |<-----------------------------------------------------------|
       |                                                            |
       | <====== Full Duplex Bidirectional Data Streaming ========> |
```

---

## 4. Keunggulan Fitur Enterprise

1. **Auto Reconnect & Health Check:**
   - Ping berkala ke proxy server (`TCP Ping` / `HTTP Head`).
   - Jika koneksi terputus, otomatis mencoba fallback/reconnect dalam interval eksponensial.
2. **Leak-Proof Kill Switch:**
   - Memanfaatkan Windows Filtering Platform (WFP) untuk memblokir seluruh outbound traffic pada adapter fisik selain trafik ke IP Proxy server itu sendiri saat koneksi tunnel drop.
3. **Multi-Threaded Ring Buffers:**
   - I/O Wintun menggunakan ring buffer berukuran 8MB - 16MB untuk transfer data tanpa bottleneck di kecepatan jaringan gigabit.
4. **Clean Exit & Recovery:**
   - Handler signal Windows (`SIGINT`, `SIGTERM`, unhandled crash) yang selalu memulihkan IP Routing Table Windows agar pengguna tidak mengalami "No Internet" saat aplikasi ditutup.

---

## 5. Rencana Struktur Proyek (Source Code)

```
socks_connector/
├── cmd/
│   └── app/                    # Entry point aplikasi utama (Wails / GUI launcher)
│   └── cli/                    # Headless CLI mode (untuk server / background task)
├── core/
│   ├── tun/                    # Wintun driver wrapper & management
│   │   ├── wintun_windows.go   # Interop Wintun DLL C API
│   │   └── device.go           # Packet reader/writer ring buffer
│   ├── stack/                  # gVisor / Userspace TCP/IP stack handler
│   │   ├── stack.go            # Netstack initialization
│   │   ├── tcp.go              # TCP connection forwarder
│   │   └── udp.go              # UDP session forwarder
│   ├── proxy/                  # Upstream Proxy Handlers
│   │   ├── socks5.go           # SOCKS5 Client with RFC 1929 Auth & UDP Assoc
│   │   ├── http.go             # HTTP/HTTPS CONNECT with Basic/Digest Auth
│   │   └── client.go           # Interface & Connection pool
│   ├── dns/                    # Fake-IP & Tunneled DNS Server
│   │   ├── fakeip.go           # 198.18.0.0/15 IP pool allocator
│   │   └── resolver.go         # Upstream DNS forwarder
│   ├── router/                 # Windows Route Manager
│   │   ├── routes_windows.go   # Win32 IP Helper route manipulation
│   │   └── killswitch.go       # WFP Kill-switch firewall rules
│   └── config/                 # Profile & Encrypted Credential Vault
│       └── profile.go          # Config storage
├── frontend/                   # Modern React / TypeScript UI (Wails)
│   ├── src/
│   │   ├── components/         # StatusCard, TrafficChart, ProfileModal, Logs
│   │   ├── App.tsx             # Main Dashboard UI
│   │   └── index.css           # Premium Dark Mode Glassmorphism CSS
│   └── package.json
├── build/
│   └── wintun/
│       ├── amd64/wintun.dll    # Official Wintun signed driver
│       └── arm64/wintun.dll
├── PRD.md                      # Product Requirements Document
├── ARCHITECTURE_FLOW.md        # Technical Architecture Document
└── wails.json / Makefile       # Build scripts & configuration
```
