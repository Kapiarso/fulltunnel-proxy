# PRODUCT REQUIREMENTS DOCUMENT (PRD)
## Project Name: Enterprise Windows Full-Tunnel Proxy Connector (SecureTunnel Enterprise)
**Version:** 1.0.0  
**Target Platform:** Windows 10 / 11 / Windows Server (x64, ARM64)  
**Document Status:** Ready for Review  

---

## 1. Executive Summary & Problem Statement

### 1.1 Problem
* **Windows Native Proxy Limitations:** Pengaturan proxy bawaan Windows (WinINet / System Proxy) hanya mengalihkan trafik dari aplikasi HTTP/HTTPS yang patuh pada proxy (seperti browser). Trafik UDP, game, tool developer (Docker, Git, SSH, Python, Node.js), serta aplikasi desktop lainnya membypass proxy secara diam-diam.
* **Authentication Flaws:** Windows system proxy tidak mendukung autentikasi SOCKS5 secara native, dan sering gagal/menampilkan popup credential yang error pada upstream proxy berautentikasi (Username & Password RFC 1928/1929).
* **DNS & Traffic Leaks:** DNS query tetap bocor melalui adapter fisik ISP (DNS Leakage), membuka celah privasi & kegagalan koneksi di lingkungan korporat/restriktif.

### 1.2 Solution
Membangun **Enterprise-Grade Full-Tunnel Proxy Connector** untuk Windows yang:
1. Menangkap **100% trafik jaringan OS** (TCP, UDP, ICMP, DNS) pada level network adapter (Layer 3) menggunakan driver kernel **Wintun**.
2. Meneruskan seluruh trafik ke upstream proxy (**SOCKS5 with Username/Password Auth**, **HTTP/HTTPS CONNECT Auth**, dan protokol enterprise lainnya).
3. Mengeliminasi kebocoran data dengan **Fake-IP / Proxy DNS Engine** bawaan (Zero DNS Leak).
4. Menyediakan performa tinggi (multi-gigabit throughput, low CPU/RAM overhead) dan antarmuka GUI modern kelas enterprise.

---

## 2. Product Objectives & Target Metrics

| Metric | Target Goal | Enterprise Standard |
| :--- | :--- | :--- |
| **Tunnel Coverage** | 100% IP Packet (TCP & UDP) | Full System-Wide Tunnel |
| **Throughput** | Hingga 2.5 Gbps+ (tergantung bandwith upstream) | Ultra-low kernel-to-userspace copying |
| **Memory Footprint** | Engine Background < 30 MB RAM | Ringan & Tidak memberatkan sistem |
| **CPU Overhead** | < 1-2% saat idle, < 5% saat saturasi trafik | Efisiensi event-loop I/O & memory buffer pool |
| **DNS Leak Rate** | 0% (Zero Leak) | Integrated Smart Fake-IP/Tunneled DNS Resolver |
| **Auth Support** | SOCKS5 (RFC 1928/1929), HTTP CONNECT (Basic/Digest) | Full credential encryption in local keystore |
| **Connection Stability**| Auto-reconnect, Keepalive Heartbeat, Kill-Switch | 99.99% uptime reliability |

---

## 3. Core Features & Capabilities

### 3.1 Network Engine & Full Tunneling
* **Wintun Kernel Layer 3 Adapter:** Menggunakan driver Wintun (driver yang sama yang dipakai WireGuard dan Cloudflare WARP) dengan ring buffer berkecepatan tinggi.
* **Userspace TCP/IP Stack (gVisor Netstack / High-Performance Tun2Socks):** Menerjemahkan raw IP packets ke sesi TCP/UDP proxy secara seamless tanpa overhead virtualisasi berat.
* **Intelligent Routing Manager:**
  * Secara otomatis mengatur Windows IP Routing Table (`0.0.0.0/1` dan `128.0.0.0/1`) untuk menangkap semua trafik tanpa merusak routing lokal (LAN/Intranet bypass).
  * Auto-exclusion route untuk IP Server Proxy agar tidak terjadi loop koneksi (*routing loop prevention*).
* **Kill-Switch (WFP Integration):** Jika koneksi proxy terputus mendadak, koneksi internet otomatis dikunci agar IP asli tidak bocor.

### 3.2 Authentication & Protocol Support
* **SOCKS5 Full Support:**
  * No-Auth (0x00)
  * Username / Password Auth (0x02 - RFC 1929)
  * TCP Connect & UDP Associate (Dukungan penuh untuk game & voice chat)
* **HTTP / HTTPS CONNECT Proxy:**
  * Basic Authentication (`Proxy-Authorization: Basic ...`)
  * TLS/HTTPS Proxy encapsulation untuk anti-DPI (Deep Packet Inspection)
* **Credential Vault:** Kredensial disimpan aman menggunakan Windows DPAPI (Data Protection API) atau Windows Credential Locker.

### 3.3 Zero-Leak DNS System
* **Fake-IP Engine (198.18.0.0/15 pool) / Remote DNS Resolution:**
  * Memetakan domain name langsung di level proxy client tanpa query DNS ke ISP lokal.
  * Menghilangkan latency handshake DNS lokal dan menjamin privasi total.
* **Fallback DoH / DoT (DNS-over-HTTPS / DNS-over-TLS):** Resolusi aman langsung melalui upstream tunnel.

### 3.4 Traffic Filtering & Rules (Split Tunneling Enterprise)
* **Global Mode:** Full 100% tunnel (seluruh aplikasi).
* **Rule / Bypass Mode:**
  * Direct route untuk IP Privat / LAN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, localhost).
  * App-based bypass / Process-based routing (misal: bypass aplikasi internal kantor tertentu).
  * Domain / IP Whitelist & Blacklist.

### 3.5 Enterprise UI/UX & Operations
* **Modern GUI Dashboard:**
  * Status koneksi real-time, grafik speed test (Upload/Download Mbps), latency (ping RTT ke proxy).
  * Live connection monitor (melihat koneksi aktif per aplikasi/proses).
  * Profile Manager (menyimpan multi-profile proxy, tag, latency test).
* **System Tray & Service Integration:**
  * Minimize to system tray dengan 1-click connect/disconnect.
  * Dapat dijalankan sebagai Windows Background Service (opsional untuk server/kiosk/unattended PC).
  * Auto-start on Windows boot.

---

## 4. Non-Functional Requirements

1. **Security:**
   - Enkripsi konfigurasi lokal dan password proxy.
   - WFP (Windows Filtering Platform) filter untuk perlindungan kill-switch.
2. **Reliability:**
   - Graceful recovery saat adapter jaringan berubah (misal: ganti dari Wi-Fi ke LAN, atau setelah laptop resume dari Sleep/Hibernate).
   - Auto-clean routing table saat aplikasi crash/ditutup paksa sehingga koneksi internet pengguna tidak macet.
3. **Compatibility:**
   - Windows 10 (1809 ke atas), Windows 11, Windows Server 2019/2022.
   - Hak akses Administrator hanya dibutuhkan saat registrasi Wintun adapter / routing setup.
