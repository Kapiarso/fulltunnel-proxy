package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"socks_connector/core"
	"socks_connector/core/config"
	"socks_connector/web"
)

func main() {
	if !core.IsAdmin() {
		log.Println("[WARN] Running without Administrator privileges. Wintun adapter creation or routing updates may require Administrator rights.")
	}

	headless := flag.Bool("headless", false, "Run in headless server mode without auto-opening browser")
	autoConnect := flag.Bool("connect", false, "Automatically connect tunnel on startup")
	port := flag.Int("port", 28888, "Web dashboard & REST API port")
	flag.Parse()

	log.Println("=========================================================")
	log.Println("  SecureTunnel Enterprise - Windows Full-Tunnel Connector")
	log.Println("  Driver: Wintun L3 Ring-Buffer | Stack: gVisor Netstack")
	log.Println("  Protocols: SOCKS5 (RFC 1928/1929 Auth) & HTTP CONNECT")
	log.Println("=========================================================")

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Printf("[WARN] Failed to load config, using defaults: %v", err)
		cfg = config.DefaultConfig()
	}

	if *port > 0 {
		cfg.HTTPPort = *port
	}

	// 2. Initialize Engine
	engine := core.NewEngine(cfg)

	engine.SetStateCallback(func(s core.State, errMsg string) {
		if errMsg != "" {
			log.Printf("[TUNNEL STATE] %s (Error: %s)", s, errMsg)
		} else {
			log.Printf("[TUNNEL STATE] %s", s)
		}
	})

	// 3. Auto-connect if requested
	if *autoConnect || cfg.AutoStart {
		log.Println("[INFO] Auto-connecting tunnel...")
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := engine.Start(); err != nil {
				log.Printf("[ERROR] Auto-connect failed: %v", err)
			}
		}()
	}

	// 4. Start Web Control Server & Dashboard
	webServer := web.NewServer(engine, cfg.HTTPPort)
	go func() {
		dashboardURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.HTTPPort)
		log.Printf("[DASHBOARD] Management Dashboard running at: %s", dashboardURL)

		if !*headless {
			time.Sleep(800 * time.Millisecond)
			openBrowser(dashboardURL)
		}

		if err := webServer.Start(); err != nil {
			log.Fatalf("[FATAL] Web server exited: %v", err)
		}
	}()

	// 5. Graceful shutdown on signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("\n[INFO] Interrupt signal received! Cleaning up tunnel & routing tables...")
	_ = engine.Stop()
	log.Println("[INFO] Cleanup complete. Goodbye!")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
