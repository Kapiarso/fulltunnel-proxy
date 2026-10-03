package stats

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionInfo holds metadata about an active tunneled connection
type ConnectionInfo struct {
	ID          string    `json:"id"`
	Network     string    `json:"network"`     // "tcp" or "udp"
	Source      string    `json:"source"`      // local client IP:port
	Destination string    `json:"destination"` // target domain or IP:port
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	StartTime   time.Time `json:"start_time"`
}

// Snapshot represents current traffic statistics
type Snapshot struct {
	UploadSpeed   int64            `json:"upload_speed"`   // Bytes per sec
	DownloadSpeed int64            `json:"download_speed"` // Bytes per sec
	PeakUpload    int64            `json:"peak_upload"`    // Peak bytes per sec
	PeakDownload  int64            `json:"peak_download"`  // Peak bytes per sec
	TotalUpload   int64            `json:"total_upload"`   // Total bytes
	TotalDownload int64            `json:"total_download"` // Total bytes
	ActiveConns   int              `json:"active_conns"`
	LatencyMs     int64            `json:"latency_ms"`
	Connections   []ConnectionInfo `json:"connections"`
}

// Tracker tracks real-time traffic speeds and connection states
type Tracker struct {
	mu            sync.RWMutex
	totalUpload   atomic.Int64
	totalDownload atomic.Int64
	lastUpload    int64
	lastDownload  int64
	uploadSpeed   atomic.Int64
	downloadSpeed atomic.Int64
	peakUpload    atomic.Int64
	peakDownload  atomic.Int64
	latencyMs     atomic.Int64
	connections   map[string]*ConnectionInfo
	stopChan      chan struct{}
}

func NewTracker() *Tracker {
	t := &Tracker{
		connections: make(map[string]*ConnectionInfo),
		stopChan:    make(chan struct{}),
	}
	go t.speedMeterLoop()
	return t
}

func (t *Tracker) AddUpload(bytes int64) {
	t.totalUpload.Add(bytes)
}

func (t *Tracker) AddDownload(bytes int64) {
	t.totalDownload.Add(bytes)
}

func (t *Tracker) RegisterConn(id, network, src, dst string) *ConnectionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	conn := &ConnectionInfo{
		ID:          id,
		Network:     network,
		Source:      src,
		Destination: dst,
		StartTime:   time.Now(),
	}
	t.connections[id] = conn
	return conn
}

func (t *Tracker) UpdateConn(id string, up, down int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if conn, exists := t.connections[id]; exists {
		conn.Upload += up
		conn.Download += down
	}
}

func (t *Tracker) UnregisterConn(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.connections, id)
}

func (t *Tracker) SetLatency(ms int64) {
	t.latencyMs.Store(ms)
}

// PingProxy tests latency to proxy host
func (t *Tracker) PingProxy(proxyAddr string) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.latencyMs.Store(-1)
		return
	}
	_ = conn.Close()
	t.latencyMs.Store(time.Since(start).Milliseconds())
}

func (t *Tracker) GetSnapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	connList := make([]ConnectionInfo, 0, len(t.connections))
	for _, c := range t.connections {
		connList = append(connList, *c)
	}

	return Snapshot{
		UploadSpeed:   t.uploadSpeed.Load(),
		DownloadSpeed: t.downloadSpeed.Load(),
		PeakUpload:    t.peakUpload.Load(),
		PeakDownload:  t.peakDownload.Load(),
		TotalUpload:   t.totalUpload.Load(),
		TotalDownload: t.totalDownload.Load(),
		ActiveConns:   len(connList),
		LatencyMs:     t.latencyMs.Load(),
		Connections:   connList,
	}
}

func (t *Tracker) Stop() {
	select {
	case <-t.stopChan:
	default:
		close(t.stopChan)
	}
}

func (t *Tracker) speedMeterLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			currentUp := t.totalUpload.Load()
			currentDown := t.totalDownload.Load()

			upDiff := currentUp - t.lastUpload
			downDiff := currentDown - t.lastDownload

			if upDiff < 0 {
				upDiff = 0
			}
			if downDiff < 0 {
				downDiff = 0
			}

			t.uploadSpeed.Store(upDiff)
			t.downloadSpeed.Store(downDiff)

			if downDiff > t.peakDownload.Load() {
				t.peakDownload.Store(downDiff)
			}
			if upDiff > t.peakUpload.Load() {
				t.peakUpload.Store(upDiff)
			}

			t.lastUpload = currentUp
			t.lastDownload = currentDown
		}
	}
}

// FormatBytes formats byte counts into human-readable strings (e.g. "12.4 MB")
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
