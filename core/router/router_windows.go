package router

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"socks_connector/core/logger"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type addedRouteInfo struct {
	luid    winipcfg.LUID
	prefix  netip.Prefix
	nextHop netip.Addr
}

// RouteManager handles Windows routing table via high-performance native Win32 IP Helper API (winipcfg)
type RouteManager struct {
	mu            sync.Mutex
	tunLUID       winipcfg.LUID
	tunGateway    netip.Addr
	proxyHost     string
	proxyIPs      []netip.Addr
	addedRoutes   []addedRouteInfo
	bypassLAN     bool
	routesApplied bool
}

// NewRouteManager creates a new route manager
func NewRouteManager(tunLUID uint64, tunGatewayStr, proxyHost string, bypassLAN bool) *RouteManager {
	gw, err := netip.ParseAddr(tunGatewayStr)
	if err != nil || !gw.IsValid() {
		gw = netip.MustParseAddr("172.19.0.2")
	}

	return &RouteManager{
		tunLUID:    winipcfg.LUID(tunLUID),
		tunGateway: gw,
		proxyHost:  proxyHost,
		bypassLAN:  bypassLAN,
	}
}

// ApplyRoutes configures Windows routing table using native Win32 API safely
func (r *RouteManager) ApplyRoutes() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	logger.Info("Applying native Windows Full-Tunnel routing rules...")

	// 1. Resolve proxy host and physical interface IPs to prevent local proxy loops
	r.proxyIPs = resolveProxyAddrs(r.proxyHost)
	if localIPs := getLocalInterfaceIPs(); len(localIPs) > 0 {
		r.proxyIPs = append(r.proxyIPs, localIPs...)
	}

	// 2. Fetch entire Windows IP forward table in memory
	table, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to retrieve Windows IP forward table: %w", err)
	}

	// 3. For each proxy IP, find its exact current interface and add a /32 priority route
	for _, ip := range r.proxyIPs {
		if ip.IsLoopback() {
			continue
		}

		bestRow := findBestRouteRow(table, ip)
		if bestRow != nil {
			prefix := netip.PrefixFrom(ip, 32)
			nextHop := bestRow.NextHop.Addr()
			if !nextHop.IsValid() || nextHop.IsUnspecified() {
				nextHop = netip.Addr{}
			}

			if safeAddRoute(bestRow.InterfaceLUID, prefix, nextHop, 1) {
				r.addedRoutes = append(r.addedRoutes, addedRouteInfo{
					luid:    bestRow.InterfaceLUID,
					prefix:  prefix,
					nextHop: nextHop,
				})
				logger.Info("Added proxy bypass route: %s via NextHop %s on Interface %d", prefix, nextHop, bestRow.InterfaceLUID)
			}
		}
	}

	// 3b. Add priority routes for physical default gateways to prevent local proxy outbound loops
	for i := range table {
		row := &table[i]
		if row.DestinationPrefix.PrefixLength == 0 && row.InterfaceLUID != r.tunLUID {
			gwAddr := row.NextHop.Addr()
			// Skip virtual gateway IPs (e.g. 26.0.0.1 on virtual adapters) to prevent route table corruption
			if gwAddr.IsValid() && !gwAddr.IsUnspecified() && !gwAddr.IsLoopback() && (!gwAddr.Is4() || gwAddr.As4()[0] != 26) {
				prefix := netip.PrefixFrom(gwAddr, 32)
				if safeAddRoute(row.InterfaceLUID, prefix, gwAddr, 1) {
					r.addedRoutes = append(r.addedRoutes, addedRouteInfo{
						luid:    row.InterfaceLUID,
						prefix:  prefix,
						nextHop: gwAddr,
					})
					logger.Info("Added default gateway bypass route: %s on Interface %d", prefix, row.InterfaceLUID)
				}
			}
		}
	}

	// 4. LAN & Virtual Overlay Subnet Bypass if requested
	if r.bypassLAN {
		lanPrefixes := []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / Tailscale / Carrier Overlays
		}
		for _, lp := range lanPrefixes {
			bestRow := findBestRouteRow(table, lp.Addr())
			if bestRow != nil && bestRow.InterfaceLUID != r.tunLUID {
				nextHop := bestRow.NextHop.Addr()
				if !nextHop.IsValid() || nextHop.IsUnspecified() {
					nextHop = netip.Addr{}
				}
				if safeAddRoute(bestRow.InterfaceLUID, lp, nextHop, 1) {
					r.addedRoutes = append(r.addedRoutes, addedRouteInfo{
						luid:    bestRow.InterfaceLUID,
						prefix:  lp,
						nextHop: nextHop,
					})
				}
			}
		}
	}

	// 5. Add Full-Tunnel override routes (0.0.0.0/1 and 128.0.0.0/1) on Wintun adapter
	r1 := netip.MustParsePrefix("0.0.0.0/1")
	r2 := netip.MustParsePrefix("128.0.0.0/1")

	if safeAddRoute(r.tunLUID, r1, r.tunGateway, 5) {
		r.addedRoutes = append(r.addedRoutes, addedRouteInfo{luid: r.tunLUID, prefix: r1, nextHop: r.tunGateway})
	}
	if safeAddRoute(r.tunLUID, r2, r.tunGateway, 5) {
		r.addedRoutes = append(r.addedRoutes, addedRouteInfo{luid: r.tunLUID, prefix: r2, nextHop: r.tunGateway})
	}

	// 6. Add IPv6 Sinkhole override routes (::/1 and 8000::/1) on Wintun to prevent IPv6 leaks
	r1_v6 := netip.MustParsePrefix("::/1")
	r2_v6 := netip.MustParsePrefix("8000::/1")
	if safeAddRoute(r.tunLUID, r1_v6, netip.Addr{}, 5) {
		r.addedRoutes = append(r.addedRoutes, addedRouteInfo{luid: r.tunLUID, prefix: r1_v6, nextHop: netip.Addr{}})
	}
	if safeAddRoute(r.tunLUID, r2_v6, netip.Addr{}, 5) {
		r.addedRoutes = append(r.addedRoutes, addedRouteInfo{luid: r.tunLUID, prefix: r2_v6, nextHop: netip.Addr{}})
	}

	// 7. Configure DNS on Wintun adapter and flush Windows DNS cache
	_ = r.tunLUID.SetDNS(windows.AF_INET, []netip.Addr{r.tunGateway}, nil)
	_ = r.tunLUID.FlushDNS(windows.AF_INET)

	r.routesApplied = true
	logger.Success("Native Windows Full-Tunnel routing applied successfully.")
	return nil
}

// RestoreRoutes cleans up all routing modifications in memory
func (r *RouteManager) RestoreRoutes() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.routesApplied {
		return
	}

	logger.Info("Restoring original routing table...")

	// Remove added routes
	for _, rt := range r.addedRoutes {
		_ = rt.luid.DeleteRoute(rt.prefix, rt.nextHop)
	}
	r.addedRoutes = nil

	// Flush DNS on tun
	_ = r.tunLUID.FlushDNS(windows.AF_INET)

	r.routesApplied = false
}

func safeAddRoute(luid winipcfg.LUID, prefix netip.Prefix, nextHop netip.Addr, metric uint32) bool {
	done := make(chan bool, 1)
	go func() {
		err := luid.AddRoute(prefix, nextHop, metric)
		done <- (err == nil)
	}()

	select {
	case ok := <-done:
		return ok
	case <-time.After(2 * time.Second):
		logger.Warn("AddRoute %s timed out after 2s", prefix)
		return false
	}
}

func findBestRouteRow(table []winipcfg.MibIPforwardRow2, target netip.Addr) *winipcfg.MibIPforwardRow2 {
	var bestRow *winipcfg.MibIPforwardRow2
	bestLen := -1
	bestMetric := uint32(0xFFFFFFFF)

	for i := range table {
		p := table[i].DestinationPrefix.Prefix()
		if p.Contains(target) {
			totalMetric := table[i].Metric
			// If prefix length is more specific, always prefer it (e.g. /32 or /8 over /0)
			if p.Bits() > bestLen {
				bestLen = p.Bits()
				bestMetric = totalMetric
				bestRow = &table[i]
			} else if p.Bits() == bestLen {
				// Equal prefix length (e.g. multiple 0.0.0.0/0 default gateways)
				// Prefer the route with the lower metric (e.g. real Ethernet vs Radmin VPN)
				if totalMetric < bestMetric {
					bestMetric = totalMetric
					bestRow = &table[i]
				}
			}
		}
	}
	return bestRow
}

func resolveProxyAddrs(host string) []netip.Addr {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}

	var res []netip.Addr
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			if addr, err := netip.ParseAddr(ip4.String()); err == nil {
				res = append(res, addr)
			}
		}
	}
	return res
}

func getLocalInterfaceIPs() []netip.Addr {
	var addrs []netip.Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Name == "SecureTunnel" {
			continue
		}
		unicastAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range unicastAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					if parsed, ok := netip.ParseAddr(ip4.String()); ok == nil {
						addrs = append(addrs, parsed)
					}
				}
			}
		}
	}
	return addrs
}
