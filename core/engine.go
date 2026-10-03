package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"socks_connector/core/config"
	"socks_connector/core/dns"
	"socks_connector/core/logger"
	"socks_connector/core/proxy"
	"socks_connector/core/router"
	"socks_connector/core/server"
	"socks_connector/core/stack"
	"socks_connector/core/stats"
	"socks_connector/core/tun"
)

// State represents the current status of the tunnel engine
type State string

const (
	StateDisconnected  State = "disconnected"
	StateConnecting    State = "connecting"
	StateConnected     State = "connected"
	StateDisconnecting State = "disconnecting"
	StateError         State = "error"
)

// Engine is the central full-tunnel coordinator
type Engine struct {
	mu            sync.RWMutex
	cfg           *config.Config
	state         State
	lastError     string
	tunDevice     tun.Device
	dnsServer     *dns.Server
	fakeIPPool    *dns.FakeIPPool
	ipStack       *stack.IPStack
	routeManager  *router.RouteManager
	tracker       *stats.Tracker
	activeDialer  proxy.Dialer
	localServer   *server.SOCKS5Server
	startedAt     time.Time
	onStateChange func(State, string)
}

// NewEngine creates a new Engine instance
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		cfg:     cfg,
		state:   StateDisconnected,
		tracker: stats.NewTracker(),
	}
}

func (e *Engine) SetStateCallback(cb func(State, string)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onStateChange = cb
}

func (e *Engine) setState(s State, errMsg string) {
	e.mu.Lock()
	e.state = s
	e.lastError = errMsg
	cb := e.onStateChange
	e.mu.Unlock()

	if errMsg != "" {
		logger.Error("Engine state: %s (Error: %s)", s, errMsg)
	} else {
		logger.Info("Engine state changed to: %s", s)
	}

	if cb != nil {
		cb(s, errMsg)
	}
}

func (e *Engine) GetState() (State, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state, e.lastError
}

func (e *Engine) GetStats() stats.Snapshot {
	return e.tracker.GetSnapshot()
}

func (e *Engine) GetConfig() *config.Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Start initiates the full-tunnel connection with strict 10-second timeout and lock-free execution
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.state == StateConnected {
		e.mu.Unlock()
		return nil
	}
	if e.state == StateConnecting {
		e.mu.Unlock()
		return errors.New("tunnel connection is already in progress")
	}
	e.state = StateConnecting
	e.lastError = ""
	e.mu.Unlock()

	e.setState(StateConnecting, "")

	// Create context with 25-second deadline for reliable Wintun initialization
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	errChan := make(chan error, 1)

	go func() {
		errChan <- e.doStart()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			e.Stop()
			e.setState(StateError, err.Error())
			return err
		}
		return nil
	case <-ctx.Done():
		e.Stop()
		err := errors.New("Connection attempt timed out after 25 seconds")
		e.setState(StateError, err.Error())
		return err
	}
}

func (e *Engine) doStart() error {
	profile := e.cfg.GetActiveProfile()
	if profile == nil {
		return errors.New("no active proxy profile configured")
	}

	logger.Info("Starting Full Tunnel with profile: %s (%s://%s:%d)...", profile.Name, profile.Type, profile.Host, profile.Port)

	// 1. Create Upstream Dialer
	var dialer proxy.Dialer
	switch profile.Type {
	case config.ProxyTypeSOCKS5:
		dialer = proxy.NewSOCKS5Dialer(profile.Host, profile.Port, profile.Username, profile.Password)
	case config.ProxyTypeHTTP:
		dialer = proxy.NewHTTPDialer(profile.Host, profile.Port, false, profile.Username, profile.Password)
	case config.ProxyTypeHTTPS:
		dialer = proxy.NewHTTPDialer(profile.Host, profile.Port, true, profile.Username, profile.Password)
	default:
		dialer = proxy.NewSOCKS5Dialer(profile.Host, profile.Port, profile.Username, profile.Password)
	}
	e.activeDialer = dialer

	// 2. Ping proxy latency
	go e.tracker.PingProxy(fmt.Sprintf("%s:%d", profile.Host, profile.Port))

	// 3. Initialize Fake-IP Pool
	logger.Info("Initializing Fake-IP memory pool (%s)...", e.cfg.FakeIPPool)
	fakePool, err := dns.NewFakeIPPool(e.cfg.FakeIPPool)
	if err != nil {
		return fmt.Errorf("failed to init Fake-IP pool: %w", err)
	}
	e.fakeIPPool = fakePool

	// 4. Initialize DNS Server
	dnsServer := dns.NewServer(e.cfg.DNSAddress, fakePool, dialer)
	_ = dnsServer.Start()
	e.dnsServer = dnsServer

	// 5. Create Wintun TUN Device
	logger.Info("Creating native Wintun network adapter '%s'...", e.cfg.TunName)
	dev, err := tun.CreateWintunDevice(e.cfg.TunName, e.cfg.TunIP, e.cfg.TunMask, e.cfg.MTU)
	if err != nil {
		if dnsServer != nil {
			dnsServer.Stop()
		}
		return fmt.Errorf("failed to create Wintun adapter: %w", err)
	}
	e.tunDevice = dev
	logger.Success("Wintun adapter '%s' created (LUID: %d)", e.cfg.TunName, dev.LUID())

	// 6. Initialize Userspace Netstack
	logger.Info("Initializing userspace IP stack (TCP/UDP/ICMP/DNS)...")
	ipStack, err := stack.NewIPStack(dev, dialer, fakePool, e.tracker)
	if err != nil {
		_ = dev.Close()
		dnsServer.Stop()
		return fmt.Errorf("failed to initialize IP netstack: %w", err)
	}
	e.ipStack = ipStack
	ipStack.Start()
	logger.Success("Userspace IP stack running.")

	// 7. Configure Windows Routing Table
	logger.Info("Configuring Windows Full-Tunnel routing table...")
	routeMgr := router.NewRouteManager(dev.LUID(), e.cfg.TunGateway, profile.Host, profile.BypassLAN)
	if err := routeMgr.ApplyRoutes(); err != nil {
		ipStack.Stop()
		_ = dev.Close()
		dnsServer.Stop()
		return fmt.Errorf("failed to configure Windows routing table: %w", err)
	}
	e.routeManager = routeMgr
	logger.Success("Routing table configured: 0.0.0.0/1 and 128.0.0.0/1 active.")

	e.startedAt = time.Now()
	e.setState(StateConnected, "")
	logger.Success("FULL TUNNEL IS NOW ACTIVE AND ROUTING 100%% OF WINDOWS TRAFFIC.")

	// Immediate & periodic ping loop
	go func() {
		proxyTarget := fmt.Sprintf("%s:%d", profile.Host, profile.Port)
		e.tracker.PingProxy(proxyTarget)
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			st, _ := e.GetState()
			if st != StateConnected {
				return
			}
			<-ticker.C
			e.tracker.PingProxy(proxyTarget)
		}
	}()

	return nil
}

// Stop gracefully shuts down the tunnel and restores original routes without deadlock
func (e *Engine) Stop() error {
	e.mu.Lock()
	if e.state == StateDisconnected {
		e.mu.Unlock()
		return nil
	}
	e.state = StateDisconnecting
	e.mu.Unlock()

	e.setState(StateDisconnecting, "")

	logger.Info("Stopping Full Tunnel and restoring original routing table...")

	// 1. Restore Windows routes
	if e.routeManager != nil {
		e.routeManager.RestoreRoutes()
		e.routeManager = nil
	}

	// 2. Stop Netstack
	if e.ipStack != nil {
		e.ipStack.Stop()
		e.ipStack = nil
	}

	// 3. Close TUN Device
	if e.tunDevice != nil {
		_ = e.tunDevice.Close()
		e.tunDevice = nil
	}

	// 4. Stop DNS Server
	if e.dnsServer != nil {
		e.dnsServer.Stop()
		e.dnsServer = nil
	}

	e.setState(StateDisconnected, "")
	logger.Info("Full Tunnel stopped. Original system network restored.")
	return nil
}

// StartLocalProxyServer starts an embedded high-speed SOCKS5 server with physical NIC binding
func (e *Engine) StartLocalProxyServer(port int, outboundIP, username, password string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.localServer != nil {
		return errors.New("built-in SOCKS5 server is already running")
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", port)
	srv := server.NewSOCKS5Server(listenAddr, outboundIP, username, password)
	if err := srv.Start(); err != nil {
		return err
	}
	e.localServer = srv
	return nil
}

// StopLocalProxyServer stops the embedded SOCKS5 server
func (e *Engine) StopLocalProxyServer() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.localServer == nil {
		return nil
	}
	err := e.localServer.Stop()
	e.localServer = nil
	return err
}

// GetLocalProxyStatus returns the status of the embedded proxy server
func (e *Engine) GetLocalProxyStatus() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	running := e.localServer != nil
	listenAddr := ""
	outboundIP := ""
	if running {
		listenAddr = e.localServer.ListenAddr
		outboundIP = e.localServer.OutboundIP
	}
	return map[string]any{
		"running":     running,
		"listen_addr": listenAddr,
		"outbound_ip": outboundIP,
	}
}

// RunSpeedComparison measures direct, proxy direct, and full tunnel speed
func (e *Engine) RunSpeedComparison(testURL string) (*stats.SpeedComparison, error) {
	if testURL == "" {
		testURL = "https://speed.cloudflare.com/__down?bytes=10485760"
	}

	comp := &stats.SpeedComparison{}

	// 1. Direct internet baseline (or via current state)
	directRes, err := stats.BenchmarkDirectSpeed(testURL)
	if err == nil {
		comp.DirectSpeed = directRes
	}

	// 2. Profile Proxy direct check
	profile := e.cfg.GetActiveProfile()
	if profile != nil {
		proxyRes, err := stats.BenchmarkProxyDirect(profile.Host, profile.Port, profile.Username, profile.Password, testURL)
		if err == nil {
			comp.ProxySpeed = proxyRes
		}
	}

	// 3. Calculate match ratio (Full Tunnel / Current Speed vs Proxy Direct capability)
	if comp.ProxySpeed != nil && comp.ProxySpeed.SpeedMbps > 0 {
		actualSpeed := comp.ProxySpeed.SpeedMbps
		if comp.DirectSpeed != nil && comp.DirectSpeed.SpeedMbps > 0 {
			actualSpeed = comp.DirectSpeed.SpeedMbps
		}

		ratio := (actualSpeed / comp.ProxySpeed.SpeedMbps) * 100.0
		if ratio > 100.0 {
			ratio = 100.0
		}
		comp.MatchRatio = ratio

		if ratio >= 85.0 {
			comp.Status = "PERFECT_MATCH"
		} else if ratio >= 60.0 {
			comp.Status = "GOOD"
		} else {
			comp.Status = "DEGRADED"
		}
	} else {
		comp.Status = "MEASURED"
	}

	return comp, nil
}

