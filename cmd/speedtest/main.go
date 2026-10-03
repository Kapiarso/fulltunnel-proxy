package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"
)

// Enable Windows VT100 Virtual Terminal Processing for clean ANSI colors in CMD
func enableWindowsVirtualTerminal() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	r1, _, _ := getStdHandle.Call(uintptr(uint32(0xFFFFFFF5)))
	handle := syscall.Handle(r1)

	var mode uint32
	r2, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r2 != 0 {
		mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
		_, _, _ = setConsoleMode.Call(uintptr(handle), uintptr(mode))
	}
}

type ProxyConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

func parseProxyString(raw string) (*ProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("proxy string is empty")
	}

	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		return &ProxyConfig{
			Host: parts[0],
			Port: parts[1],
		}, nil
	case 4:
		return &ProxyConfig{
			Host:     parts[0],
			Port:     parts[1],
			Username: parts[2],
			Password: parts[3],
		}, nil
	default:
		return nil, fmt.Errorf("invalid format '%s'. Use 'IP:PORT' or 'IP:PORT:USER:PASS'", raw)
	}
}

func createSOCKS5Client(cfg *ProxyConfig, timeout time.Duration) (*http.Client, error) {
	var auth *proxy.Auth
	if cfg.Username != "" || cfg.Password != "" {
		auth = &proxy.Auth{
			User:     cfg.Username,
			Password: cfg.Password,
		}
	}

	proxyAddr := net.JoinHostPort(cfg.Host, cfg.Port)
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SOCKS5 dialer: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
				_ = tcpConn.SetReadBuffer(8 << 20)  // 8MB buffer
				_ = tcpConn.SetWriteBuffer(8 << 20) // 8MB buffer
			}
			return conn, nil
		},
		DisableKeepAlives:     false,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		ResponseHeaderTimeout: 15 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

type LatencyStats struct {
	Min    time.Duration
	Avg    time.Duration
	Max    time.Duration
	Jitter time.Duration
}

func measurePrecisionLatency(client *http.Client, samples int) *LatencyStats {
	var durations []time.Duration
	for i := 0; i < samples; i++ {
		start := time.Now()
		req, err := http.NewRequest("GET", "https://1.1.1.1", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			durations = append(durations, time.Since(start))
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(durations) == 0 {
		return nil
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	min := durations[0]
	max := durations[len(durations)-1]
	var total float64
	for _, d := range durations {
		total += float64(d.Milliseconds())
	}
	avgMs := total / float64(len(durations))

	var variance float64
	for _, d := range durations {
		diff := float64(d.Milliseconds()) - avgMs
		variance += diff * diff
	}
	jitterMs := math.Sqrt(variance / float64(len(durations)))

	return &LatencyStats{
		Min:    min,
		Avg:    time.Duration(avgMs * float64(time.Millisecond)),
		Max:    max,
		Jitter: time.Duration(jitterMs * float64(time.Millisecond)),
	}
}

func getPublicIP(client *http.Client) string {
	req, _ := http.NewRequest("GET", "https://api.ipify.org", nil)
	resp, err := client.Do(req)
	if err != nil {
		req, _ = http.NewRequest("GET", "https://ifconfig.me/ip", nil)
		resp, err = client.Do(req)
		if err != nil {
			return "Unknown / Proxy Timeout"
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(body))
}

// Ultra-Precision Download Engine:
// Uses 8 Parallel Streams + 2s TCP Window Warm-Up + Peak Steady-State Measurement
func testUltraPrecisionDownload(cfg *ProxyConfig, numStreams int, warmUpSec int, testSec int) float64 {
	fmt.Printf("\n[ULTRA-PRECISION DOWNLOAD] Initializing %d parallel streams (Warm-up: %ds | Steady-state: %ds)...\n",
		numStreams, warmUpSec, testSec)

	// High-speed CDN endpoints
	cdnUrls := []string{
		"https://speed.cloudflare.com/__down?bytes=50000000",
		"https://proof.ovh.net/files/100Mb.dat",
	}

	totalDuration := warmUpSec + testSec
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(totalDuration)*time.Second)
	defer cancel()

	var totalBytes int64
	var steadyBytes int64
	var maxObservedMbps float64

	start := time.Now()
	var warmUpEnd time.Time
	isWarmUpDone := false

	stopChan := make(chan struct{})

	// Progress & Speed Meter
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				now := time.Now()
				bytesSoFar := atomic.LoadInt64(&totalBytes)
				elapsed := now.Sub(start).Seconds()

				if !isWarmUpDone && elapsed >= float64(warmUpSec) {
					isWarmUpDone = true
					warmUpEnd = now
					atomic.StoreInt64(&steadyBytes, 0)
				}

				if elapsed > 0.05 {
					mbps := (float64(bytesSoFar) * 8) / (elapsed * 1000 * 1000)
					if isWarmUpDone {
						sBytes := atomic.LoadInt64(&steadyBytes)
						sElapsed := now.Sub(warmUpEnd).Seconds()
						if sElapsed > 0.05 {
							mbps = (float64(sBytes) * 8) / (sElapsed * 1000 * 1000)
						}
					}
					if mbps > maxObservedMbps {
						maxObservedMbps = mbps
					}

					phase := "WARM-UP"
					if isWarmUpDone {
						phase = "BENCHMARKING"
					}

					fmt.Printf("\r   --> Phase: %s | Active Streams: %d | Data: %.2f MB | Speed: %.2f Mbps (%.2f MB/s) [Peak: %.2f Mbps]   ",
						phase, numStreams, float64(bytesSoFar)/(1024*1024), mbps, float64(bytesSoFar)/(elapsed*1024*1024), maxObservedMbps)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(streamID int) {
			defer wg.Done()
			client, err := createSOCKS5Client(cfg, 30*time.Second)
			if err != nil {
				return
			}

			targetURL := cdnUrls[streamID%len(cdnUrls)]
			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			buf := make([]byte, 128*1024)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					n, err := resp.Body.Read(buf)
					if n > 0 {
						atomic.AddInt64(&totalBytes, int64(n))
						if isWarmUpDone {
							atomic.AddInt64(&steadyBytes, int64(n))
						}
					}
					if err != nil {
						return
					}
				}
			}
		}(i)
	}

	wg.Wait()
	close(stopChan)
	endTime := time.Now()

	sBytes := atomic.LoadInt64(&steadyBytes)
	sElapsed := endTime.Sub(warmUpEnd).Seconds()
	if sElapsed <= 0.5 {
		sBytes = atomic.LoadInt64(&totalBytes)
		sElapsed = endTime.Sub(start).Seconds()
	}

	steadyMbps := (float64(sBytes) * 8) / (sElapsed * 1000 * 1000)

	// Return the maximum of steady-state speed and peak observed speed
	finalSpeed := steadyMbps
	if maxObservedMbps > finalSpeed {
		finalSpeed = maxObservedMbps
	}

	fmt.Printf("\r   [SUCCESS] Multi-Stream Download: Total %.2f MB | Steady Speed: %.2f Mbps (%.2f MB/s) | PEAK: %.2f Mbps   \n",
		float64(atomic.LoadInt64(&totalBytes))/(1024*1024), steadyMbps, steadyMbps/8.0, finalSpeed)
	return finalSpeed
}

// Ultra-Precision Upload Engine:
// Uses 8 Parallel Streams + 10MB Chunks per Stream
func testUltraPrecisionUpload(cfg *ProxyConfig, numStreams int, payloadMBPerStream int) float64 {
	fmt.Printf("\n[ULTRA-PRECISION UPLOAD] Initializing %d parallel streams (%dMB per stream)...\n",
		numStreams, payloadMBPerStream)

	sizeBytes := payloadMBPerStream * 1024 * 1024
	payload := make([]byte, sizeBytes)
	_, _ = rand.Read(payload)

	uploadURL := "https://speed.cloudflare.com/__up"

	var totalBytes int64
	var maxObservedMbps float64

	start := time.Now()
	stopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				bytesSoFar := atomic.LoadInt64(&totalBytes)
				elapsed := time.Since(start).Seconds()
				if elapsed > 0.05 {
					mbps := (float64(bytesSoFar) * 8) / (elapsed * 1000 * 1000)
					if mbps > maxObservedMbps {
						maxObservedMbps = mbps
					}
					fmt.Printf("\r   --> Active Streams: %d | Data Sent: %.2f MB | Live Speed: %.2f Mbps (%.2f MB/s) [Peak: %.2f Mbps]   ",
						numStreams, float64(bytesSoFar)/(1024*1024), mbps, float64(bytesSoFar)/(elapsed*1024*1024), maxObservedMbps)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(streamID int) {
			defer wg.Done()
			client, err := createSOCKS5Client(cfg, 30*time.Second)
			if err != nil {
				return
			}
			req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(payload))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.ContentLength = int64(sizeBytes)

			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddInt64(&totalBytes, int64(sizeBytes))
			}
		}(i)
	}

	wg.Wait()
	close(stopChan)
	elapsed := time.Since(start).Seconds()
	finalBytes := atomic.LoadInt64(&totalBytes)

	if finalBytes == 0 {
		fmt.Printf("\r   [FAILED] Multi-Stream Upload failed.                                              \n")
		return 0
	}

	mbps := (float64(finalBytes) * 8) / (elapsed * 1000 * 1000)
	finalSpeed := mbps
	if maxObservedMbps > finalSpeed {
		finalSpeed = maxObservedMbps
	}

	fmt.Printf("\r   [SUCCESS] Multi-Stream Upload: Total %.2f MB in %.2fs -> SPEED: %.2f Mbps (%.2f MB/s) | PEAK: %.2f Mbps   \n",
		float64(finalBytes)/(1024*1024), elapsed, mbps, float64(finalBytes)/(elapsed*1024*1024), finalSpeed)
	return finalSpeed
}

func main() {
	enableWindowsVirtualTerminal()

	fmt.Println("============================================================================")
	fmt.Println("  ENTERPRISE SOCKS5 SPEEDTEST PRO (Ultra-Precision Multi-Stream Engine)")
	fmt.Println("============================================================================")

	var rawInput string
	if len(os.Args) > 1 {
		rawInput = os.Args[1]
	} else {
		fmt.Print("Enter SOCKS5 Proxy (IP:PORT or IP:PORT:USER:PASS): ")
		fmt.Scanln(&rawInput)
	}

	cfg, err := parseProxyString(rawInput)
	if err != nil {
		fmt.Printf("\n[ERROR] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[INFO] Connecting to SOCKS5 Proxy: %s:%s", cfg.Host, cfg.Port)
	if cfg.Username != "" {
		fmt.Printf(" (Auth User: %s)", cfg.Username)
	}
	fmt.Println("...")

	client, err := createSOCKS5Client(cfg, 10*time.Second)
	if err != nil {
		fmt.Printf("\n[ERROR] %v\n", err)
		os.Exit(1)
	}

	// 1. Precision Latency & Jitter Test
	fmt.Print("[TEST] Measuring Latency & Jitter (5 Precision Samples)... ")
	latStats := measurePrecisionLatency(client, 5)
	if latStats == nil {
		fmt.Println("FAILED (Proxy unreachable or handshake timeout)")
		os.Exit(1)
	}
	fmt.Printf("SUCCESS\n")
	fmt.Printf("   --> Latency: Min: %dms | Avg: %dms | Max: %dms | Jitter: %.1fms\n",
		latStats.Min.Milliseconds(), latStats.Avg.Milliseconds(), latStats.Max.Milliseconds(),
		float64(latStats.Jitter.Microseconds())/1000.0)

	// 2. Public IP Verification
	fmt.Print("[TEST] Verifying Proxy Outbound Public IP... ")
	publicIP := getPublicIP(client)
	fmt.Printf("%s\n", publicIP)

	// 3. Ultra-Precision Multi-Stream Download (8 Parallel Streams, 2s Warm-Up + 6s Measurement)
	downSpeed := testUltraPrecisionDownload(cfg, 8, 2, 6)

	// 4. Ultra-Precision Multi-Stream Upload (8 Parallel Streams, 10MB per stream = 80MB total)
	upSpeed := testUltraPrecisionUpload(cfg, 8, 10)

	// Final Summary Report
	fmt.Println("\n============================================================================")
	fmt.Println("                   HIGH-PRECISION BENCHMARK SUMMARY                         ")
	fmt.Println("============================================================================")
	fmt.Printf(" Target Proxy:        %s:%s\n", cfg.Host, cfg.Port)
	fmt.Printf(" Outbound Public IP:  %s\n", publicIP)
	fmt.Printf(" Ping Latency (Avg):  %d ms (Min: %dms, Max: %dms)\n", latStats.Avg.Milliseconds(), latStats.Min.Milliseconds(), latStats.Max.Milliseconds())
	fmt.Printf(" Connection Jitter:   %.2f ms\n", float64(latStats.Jitter.Microseconds())/1000.0)
	fmt.Printf(" Download Speed:      %.2f Mbps (%.2f MB/s)\n", downSpeed, downSpeed/8.0)
	fmt.Printf(" Upload Speed:        %.2f Mbps (%.2f MB/s)\n", upSpeed, upSpeed/8.0)
	fmt.Println("============================================================================")
}
