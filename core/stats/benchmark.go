package stats

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"socks_connector/core/proxy"
)

// SpeedResult holds benchmark measurements
type SpeedResult struct {
	BytesDownloaded int64   `json:"bytes"`
	DurationMs      int64   `json:"duration_ms"`
	SpeedMbps       float64 `json:"speed_mbps"`
	SpeedMBs        float64 `json:"speed_mbs"`
	LatencyMs       int64   `json:"latency_ms"`
}

// SpeedComparison compares direct vs proxy vs full tunnel
type SpeedComparison struct {
	DirectSpeed     *SpeedResult `json:"direct_speed"`
	ProxySpeed      *SpeedResult `json:"proxy_speed"`
	FullTunnelSpeed *SpeedResult `json:"full_tunnel_speed"`
	MatchRatio      float64      `json:"match_ratio"` // Percentage matching direct baseline (e.g. 98.5%)
	Status          string       `json:"status"`      // "PERFECT_MATCH", "GOOD", "DEGRADED"
}

var BenchmarkURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=10485760",
	"https://proof.ovh.net/files/10Mb.dat",
}

// RunBenchmark measures multi-stream parallel download speed for high accuracy within 3 seconds
func RunBenchmark(client *http.Client, testURL string) (*SpeedResult, error) {
	if testURL == "" {
		testURL = BenchmarkURLs[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	numStreams := 2
	var totalRead atomic.Int64
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			defer resp.Body.Close()

			buf := make([]byte, 32*1024)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				n, rErr := resp.Body.Read(buf)
				if n > 0 {
					totalRead.Add(int64(n))
				}
				if rErr != nil {
					break
				}
			}
		}()
	}

	wg.Wait()
	dur := time.Since(start)
	if dur < 100*time.Millisecond {
		dur = 100 * time.Millisecond
	}
	totalBytes := totalRead.Load()

	if totalBytes == 0 {
		return nil, fmt.Errorf("zero bytes received from speedtest target")
	}

	mbps := float64(totalBytes*8) / (dur.Seconds() * 1000 * 1000)
	mbs := float64(totalBytes) / (dur.Seconds() * 1024 * 1024)

	return &SpeedResult{
		BytesDownloaded: totalBytes,
		DurationMs:      dur.Milliseconds(),
		SpeedMbps:       mbps,
		SpeedMBs:        mbs,
	}, nil
}

// BenchmarkDirectSpeed tests raw physical internet speed
func BenchmarkDirectSpeed(testURL string) (*SpeedResult, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			MaxIdleConnsPerHost: 16,
		},
		Timeout: 6 * time.Second,
	}
	return RunBenchmark(client, testURL)
}

// BenchmarkProxyDirect tests direct SOCKS5 connection to proxy
func BenchmarkProxyDirect(proxyHost string, proxyPort int, user, pass, testURL string) (*SpeedResult, error) {
	dialer := proxy.NewSOCKS5Dialer(proxyHost, proxyPort, user, pass)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConnsPerHost: 16,
		},
		Timeout: 6 * time.Second,
	}
	return RunBenchmark(client, testURL)
}
