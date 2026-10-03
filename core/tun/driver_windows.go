package tun

import (
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

//go:embed wintun_amd64.dll
var embeddedWintunDLL []byte

// Device represents a TUN network interface
type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
	LUID() uint64
}

// WintunDevice implements the Device interface using official Wintun driver + winipcfg
type WintunDevice struct {
	adapter   *wintun.Adapter
	session   wintun.Session
	name      string
	mtu       int
	readWait  windows.Handle
	closeOnce sync.Once
	closed    chan struct{}
}

// EnsureWintunDLL makes sure matching wintun.dll is available in current folder or extracted from binary
func EnsureWintunDLL() error {
	if _, err := os.Stat("wintun.dll"); os.IsNotExist(err) {
		if len(embeddedWintunDLL) > 0 {
			_ = os.WriteFile("wintun.dll", embeddedWintunDLL, 0755)
		}
	}

	absPath, err := filepath.Abs("wintun.dll")
	if err == nil {
		handle, err := windows.LoadLibrary(absPath)
		if err == nil && handle != 0 {
			return nil
		}
	}

	return nil
}

// CreateWintunDevice creates or opens a Wintun adapter and configures IP via native winipcfg
func CreateWintunDevice(name string, ipStr, maskStr string, mtu int) (*WintunDevice, error) {
	if err := EnsureWintunDLL(); err != nil {
		return nil, fmt.Errorf("failed to prepare wintun.dll: %w", err)
	}

	if mtu <= 0 {
		mtu = 1500
	}

	tunnelType := "SecureTunnel"
	var adapter *wintun.Adapter
	var session wintun.Session
	var err error

	// 1. Open or create Wintun adapter with robust retry loop
	for attempt := 0; attempt < 10; attempt++ {
		adapter, err = wintun.OpenAdapter(name)
		if err == nil {
			session, err = adapter.StartSession(0x1000000) // 16MB ring buffer
			if err == nil {
				break
			}
			// If session is already initialized, close adapter handle and wait for NDIS release
			_ = adapter.Close()
			adapter = nil
			time.Sleep(300 * time.Millisecond)
		}

		adapter, err = wintun.CreateAdapter(name, tunnelType, nil)
		if err == nil {
			session, err = adapter.StartSession(0x1000000)
			if err == nil {
				break
			}
			_ = adapter.Close()
			adapter = nil
		}
		time.Sleep(300 * time.Millisecond)
	}

	if err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			return nil, fmt.Errorf("Administrator privileges required to create Wintun network adapter (Access is denied). Please right-click securetunnel.exe and select 'Run as administrator'")
		}
		return nil, fmt.Errorf("failed to start Wintun adapter session after retries: %v", err)
	}

	dev := &WintunDevice{
		adapter:  adapter,
		session:  session,
		name:     name,
		mtu:      mtu,
		readWait: session.ReadWaitEvent(),
		closed:   make(chan struct{}),
	}

	// 2. Configure IP and DNS via native Windows IP Helper API (winipcfg) - Instant & Zero-Hang!
	luid := winipcfg.LUID(adapter.LUID())
	
	// Parse CIDR
	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/30", ipStr))
	if err != nil {
		prefix = netip.MustParsePrefix("172.19.0.1/30")
	}

	prefixV6 := netip.MustParsePrefix("fdfe:dcba:9876::1/126")
	if err := luid.SetIPAddresses([]netip.Prefix{prefix, prefixV6}); err != nil {
		_ = luid.SetIPAddresses([]netip.Prefix{prefix})
	}

	// Set MTU and high priority interface metric
	if ipIface, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipIface.NLMTU = uint32(mtu)
		ipIface.Metric = 1
		_ = ipIface.Set()
	}
	if ipIface6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipIface6.NLMTU = uint32(mtu)
		ipIface6.Metric = 1
		_ = ipIface6.Set()
	}

	// Configure DNS Server (172.19.0.2 Fake-IP DNS Engine) on Wintun adapter
	dnsAddr := netip.MustParseAddr("172.19.0.2")
	_ = luid.SetDNS(windows.AF_INET, []netip.Addr{dnsAddr}, nil)
	_ = luid.FlushDNS(windows.AF_INET)

	return dev, nil
}

func (w *WintunDevice) Read(p []byte) (int, error) {
	for {
		select {
		case <-w.closed:
			return 0, io.EOF
		default:
		}

		packet, err := w.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			w.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		switch err {
		case windows.ERROR_HANDLE_EOF, windows.ERROR_INVALID_DATA:
			return 0, io.EOF
		case windows.ERROR_NO_MORE_ITEMS:
			windows.WaitForSingleObject(w.readWait, windows.INFINITE)
			continue
		default:
			return 0, err
		}
	}
}

func (w *WintunDevice) Write(p []byte) (int, error) {
	select {
	case <-w.closed:
		return 0, io.EOF
	default:
	}

	for i := 0; i < 200; i++ {
		packet, err := w.session.AllocateSendPacket(len(p))
		if err == nil {
			copy(packet, p)
			w.session.SendPacket(packet)
			return len(p), nil
		}
		if i < 20 {
			runtime.Gosched()
		} else {
			time.Sleep(10 * time.Microsecond)
		}
	}

	return 0, fmt.Errorf("wintun send ring buffer full")
}

func (w *WintunDevice) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.closed)
		w.session.End()
		if w.adapter != nil {
			err = w.adapter.Close()
		}
	})
	return err
}

func (w *WintunDevice) Name() string {
	return w.name
}

func (w *WintunDevice) MTU() int {
	return w.mtu
}

func (w *WintunDevice) LUID() uint64 {
	if w.adapter != nil {
		return w.adapter.LUID()
	}
	return 0
}
