package stack

import (
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	modiphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	AF_INET                 = 2
	TCP_TABLE_OWNER_PID_ALL = 5
)

type mibTcpRowOwnerPid struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
	owningPid  uint32
}

// GetPIDForLocalPort returns the Process ID (PID) owning the specified local TCP port on Windows
func GetPIDForLocalPort(port uint16) uint32 {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if size == 0 {
		return 0
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)
	if ret != 0 {
		return 0
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	entrySize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	baseOffset := uintptr(4)

	targetPortNetworkOrder := ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)

	for i := uint32(0); i < numEntries; i++ {
		entryPtr := (*mibTcpRowOwnerPid)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + baseOffset + uintptr(i)*entrySize))
		if entryPtr.localPort == uint32(targetPortNetworkOrder) {
			return entryPtr.owningPid
		}
	}
	return 0
}

var (
	cachedIfIndex   uint32
	cachedLocalIP   net.IP
	cachedGatewayIP net.IP
	cacheMu         sync.RWMutex
	lastCacheTime   time.Time
)

func updatePhysicalAdapterCacheLocked() {
	if time.Since(lastCacheTime) < 10*time.Second && cachedIfIndex > 0 {
		return
	}

	table, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err == nil {
		var bestRow *winipcfg.MibIPforwardRow2
		var bestMetric uint32 = 0xFFFFFFFF
		for i := range table {
			row := &table[i]
			if row.DestinationPrefix.PrefixLength == 0 {
				gw := row.NextHop.Addr()
				if gw.IsValid() && !gw.IsUnspecified() && !gw.IsLoopback() {
					b := gw.As4()
					// Exclude Radmin VPN (26.x), Wintun (172.19.x), APIPA (169.254.x)
					if b[0] == 26 || (b[0] == 172 && b[1] == 19) || (b[0] == 169 && b[1] == 254) {
						continue
					}
					if row.Metric < bestMetric {
						bestMetric = row.Metric
						bestRow = row
					}
				}
			}
		}
		if bestRow != nil {
			cachedIfIndex = bestRow.InterfaceIndex
			gw := bestRow.NextHop.Addr()
			cachedGatewayIP = net.IP(gw.AsSlice())

			iface, errIface := net.InterfaceByIndex(int(cachedIfIndex))
			if errIface == nil {
				addrs, errAddrs := iface.Addrs()
				if errAddrs == nil {
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
							ip := ipnet.IP.To4()
							if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() {
								cachedLocalIP = ip
								break
							}
						}
					}
				}
			}
			lastCacheTime = time.Now()
			return
		}
	}

	// Fallback to iterating interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				name := iface.Name
				if name == "SecureTunnel" || name == "Radmin VPN" || strings.HasPrefix(name, "VMware") || strings.HasPrefix(name, "VirtualBox") {
					continue
				}
				addrs, errAddrs := iface.Addrs()
				if errAddrs != nil {
					continue
				}
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
						ip := ipnet.IP.To4()
						if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && ip[0] != 26 && !(ip[0] == 172 && ip[1] == 19) {
							cachedIfIndex = uint32(iface.Index)
							cachedLocalIP = ip
							break
						}
					}
				}
				if cachedIfIndex > 0 {
					break
				}
			}
		}
	}
	lastCacheTime = time.Now()
}

// GetPhysicalInterfaceIndex returns the Windows interface index of the primary physical internet adapter
func GetPhysicalInterfaceIndex() uint32 {
	cacheMu.RLock()
	if cachedIfIndex > 0 && time.Since(lastCacheTime) < 10*time.Second {
		val := cachedIfIndex
		cacheMu.RUnlock()
		return val
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	updatePhysicalAdapterCacheLocked()
	return cachedIfIndex
}

// GetPhysicalLocalIP returns the IPv4 address of the primary physical adapter (Wi-Fi/Ethernet)
func GetPhysicalLocalIP() net.IP {
	cacheMu.RLock()
	if cachedLocalIP != nil && time.Since(lastCacheTime) < 10*time.Second {
		val := cachedLocalIP
		cacheMu.RUnlock()
		return val
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	updatePhysicalAdapterCacheLocked()
	return cachedLocalIP
}

// GetPhysicalGatewayIP returns the default gateway IP of the physical adapter
func GetPhysicalGatewayIP() net.IP {
	cacheMu.RLock()
	if cachedGatewayIP != nil && time.Since(lastCacheTime) < 10*time.Second {
		val := cachedGatewayIP
		cacheMu.RUnlock()
		return val
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	updatePhysicalAdapterCacheLocked()
	return cachedGatewayIP
}
