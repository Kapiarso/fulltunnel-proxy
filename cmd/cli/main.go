package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"socks_connector/core"
	"socks_connector/core/config"
	"socks_connector/core/stats"
)

func main() {
	if !core.IsAdmin() {
		log.Println("[WARN] Running without Administrator privileges. Wintun adapter creation or routing updates may require Administrator rights.")
	}

	proxyStr := flag.String("proxy", "", "Proxy string in IP:PORT or IP:PORT:USER:PASS format")
	host := flag.String("host", "", "Upstream proxy server IP or domain")
	port := flag.Int("port", 1080, "Upstream proxy port")
	proto := flag.String("type", "socks5", "Proxy type: socks5, http, https")
	user := flag.String("user", "", "Username for authentication (RFC 1929)")
	pass := flag.String("pass", "", "Password for authentication")
	flag.Parse()

	// Check positional arg (e.g. `securetunnel-cli.exe 127.0.0.1:1080`)
	args := flag.Args()
	if len(args) > 0 && *proxyStr == "" && *host == "" {
		*proxyStr = args[0]
	}

	if *proxyStr != "" {
		parsedHost, parsedPort, parsedUser, parsedPass, err := parseProxyString(*proxyStr)
		if err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
		*host = parsedHost
		*port = parsedPort
		if parsedUser != "" {
			*user = parsedUser
		}
		if parsedPass != "" {
			*pass = parsedPass
		}
	}

	if *host == "" {
		fmt.Println("FullTunnel Enterprise CLI - Windows Full-Tunnel Connector")
		fmt.Println("\nUsage:")
		fmt.Println("  1-Liner: fulltunnel-cli.exe <IP:PORT> atau <IP:PORT:USER:PASS>")
		fmt.Println("  Flags:   fulltunnel-cli.exe -proxy <IP:PORT:USER:PASS> [-type socks5|http]")
		fmt.Println("  Detail:  fulltunnel-cli.exe -host <IP> -port <PORT> [-user <USER>] [-pass <PASS>]")
		fmt.Println("\nContoh:")
		fmt.Println("  fulltunnel-cli.exe 127.0.0.1:1080")
		fmt.Println("  fulltunnel-cli.exe 198.51.100.1:1080:username:password")
		os.Exit(1)
	}

	cfg := config.DefaultConfig()
	cfg.Profiles = []config.Profile{
		{
			ID:        "cli-profile",
			Name:      "CLI Direct Tunnel",
			Type:      config.ProxyType(*proto),
			Host:      *host,
			Port:      *port,
			Username:  *user,
			Password:  *pass,
			EnableUDP: true,
			DNSMode:   config.DNSModeFakeIP,
			BypassLAN: true,
		},
	}
	cfg.ActiveProfileID = "cli-profile"

	log.Printf("[CLI] Initializing Enterprise Tunnel -> %s://%s:%d (User: %s)", *proto, *host, *port, *user)
	engine := core.NewEngine(cfg)

	engine.SetStateCallback(func(s core.State, errMsg string) {
		log.Printf("[STATE] %s %s", s, errMsg)
	})

	if err := engine.Start(); err != nil {
		log.Fatalf("[FATAL] Failed to start tunnel: %v", err)
	}

	log.Println("[SUCCESS] Full tunnel active! Press Ctrl+C to disconnect and restore routes.")

	// Stats ticker
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			st := engine.GetStats()
			log.Printf("[METRICS] Speed: Down %s/s | Up %s/s | Active Conns: %d | Total: Down %s / Up %s",
				stats.FormatBytes(st.DownloadSpeed),
				stats.FormatBytes(st.UploadSpeed),
				st.ActiveConns,
				stats.FormatBytes(st.TotalDownload),
				stats.FormatBytes(st.TotalUpload),
			)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[INFO] Restoring routing tables...")
	_ = engine.Stop()
	log.Println("[INFO] Disconnected cleanly.")
}

func parseProxyString(raw string) (host string, port int, user, pass string, err error) {
	raw = strings.TrimSpace(raw)
	// Strip proto prefix if user included it e.g. "socks5://"
	if strings.Contains(raw, "://") {
		parts := strings.SplitN(raw, "://", 2)
		raw = parts[1]
	}

	parts := strings.Split(raw, ":")
	if len(parts) < 2 {
		return "", 0, "", "", fmt.Errorf("format proxy tidak valid. Gunakan IP:PORT atau IP:PORT:USER:PASS")
	}

	host = parts[0]
	p, err := strconv.Atoi(parts[1])
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, "", "", fmt.Errorf("port proxy tidak valid: %s", parts[1])
	}
	port = p

	if len(parts) >= 4 {
		user = parts[2]
		pass = parts[3]
	}

	return host, port, user, pass, nil
}
