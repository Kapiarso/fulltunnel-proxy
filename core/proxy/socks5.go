package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	socksVersion5 = 0x05

	// Auth methods
	socksAuthNone     = 0x00
	socksAuthUserPass = 0x02
	socksAuthNoAccept = 0xFF

	// Commands
	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03

	// Address types
	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04
)

// OptimizeRadminP2PTunnel sends UDP NAT hole-punching packets to target IP on Radmin P2P ports
func OptimizeRadminP2PTunnel(targetHost string) {
	host, _, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.To4()[0] != 26 {
		return
	}

	// Send UDP hole punching packets to Radmin P2P ports 48650, 17777, 3478
	ports := []int{48650, 17777, 3478}
	dummyPayload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	for _, port := range ports {
		go func(p int) {
			addr := net.JoinHostPort(host, strconv.Itoa(p))
			conn, err := net.DialTimeout("udp", addr, 1*time.Second)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = conn.Write(dummyPayload)
				_ = conn.Close()
			}
		}(port)
	}
}

// SOCKS5Dialer implements the SOCKS5 proxy client protocol with RFC 1929 auth
type SOCKS5Dialer struct {
	ProxyAddr string
	Username  string
	Password  string
	Timeout   time.Duration
}

// NewSOCKS5Dialer creates a new SOCKS5 proxy dialer
func NewSOCKS5Dialer(host string, port int, username, password string) *SOCKS5Dialer {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	OptimizeRadminP2PTunnel(target)
	return &SOCKS5Dialer{
		ProxyAddr: target,
		Username:  username,
		Password:  password,
		Timeout:   10 * time.Second,
	}
}

func (s *SOCKS5Dialer) Protocol() string {
	return "socks5"
}

func (s *SOCKS5Dialer) TargetServer() string {
	return s.ProxyAddr
}

// Dial connects to the target address through the SOCKS5 proxy
func (s *SOCKS5Dialer) Dial(network, address string) (net.Conn, error) {
	return s.DialContext(context.Background(), network, address)
}

// DialContext connects to the target address through the SOCKS5 proxy with context support
func (s *SOCKS5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = s.Timeout
	if d.Timeout == 0 {
		d.Timeout = 10 * time.Second
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, 16<<20) // 16MB Pre-connect Window Scale (Proxifier-Titan Engine)
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, 16<<20) // 16MB Send Buffer
			_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_NODELAY, 1)
		})
	}

	var conn net.Conn
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		conn, err = d.DialContext(ctx, "tcp", s.ProxyAddr)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("failed to connect to SOCKS5 proxy %s: %w", s.ProxyAddr, err)
		}
		time.Sleep(15 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy %s: %w", s.ProxyAddr, err)
	}

	// --- Enterprise TCP optimizations on upstream SOCKS5 connection ---
	// 1. TCP_NODELAY: disable Nagle's algorithm for low-latency small writes
	// 2. SO_RCVBUF/SO_SNDBUF: 2MB socket buffers for high-throughput Gbps scaling without kernel buffer exhaustion under multitasking
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(2 << 20)  // 2MB recv buffer
		_ = tcpConn.SetWriteBuffer(2 << 20) // 2MB send buffer
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Standard 100% RFC 1928 compliant SOCKS5 negotiation (compatible with all external proxy servers)
	if err := s.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	if err := s.connect(conn, address); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// pipelinedConnect sends SOCKS5 Greeting and CONNECT in a single 1-RTT TCP write
func (s *SOCKS5Dialer) pipelinedConnect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid destination target %s: %w", target, err)
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid destination port %s: %w", portStr, err)
	}

	// 1. Build combined payload [Greeting (3 bytes) + CONNECT command]
	buf := make([]byte, 0, 32+len(host))
	buf = append(buf, socksVersion5, 0x01, socksAuthNone) // Greeting
	buf = append(buf, socksVersion5, socksCmdConnect, 0x00) // CONNECT header

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, socksAtypIPv4)
		buf = append(buf, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		buf = append(buf, socksAtypIPv6)
		buf = append(buf, ip6...)
	} else {
		if len(host) > 255 {
			return errors.New("destination domain name exceeds 255 bytes")
		}
		buf = append(buf, socksAtypDomain, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	buf = append(buf, byte(portNum>>8), byte(portNum&0xFF))

	// Send combined greeting + connect request in single TCP write
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send pipelined SOCKS5 request: %w", err)
	}

	// 2. Read greeting response (2 bytes)
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetResp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 greeting response: %w", err)
	}
	if greetResp[0] != socksVersion5 || greetResp[1] != socksAuthNone {
		return fmt.Errorf("SOCKS5 proxy rejected no-auth greeting: 0x%02x 0x%02x", greetResp[0], greetResp[1])
	}

	// 3. Read connect response header (4 bytes)
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return fmt.Errorf("failed to read SOCKS5 CONNECT response header: %w", err)
	}
	if respHeader[0] != socksVersion5 {
		return fmt.Errorf("invalid SOCKS5 response version: 0x%02x", respHeader[0])
	}
	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 server returned connect error code: 0x%02x (%s)", respHeader[1], socksErrorString(respHeader[1]))
	}

	// Drain bound address field
	var addrLen int
	switch respHeader[3] {
	case socksAtypIPv4:
		addrLen = 4
	case socksAtypIPv6:
		addrLen = 16
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("failed to read SOCKS5 domain length: %w", err)
		}
		addrLen = int(lenBuf[0])
	default:
		return fmt.Errorf("unsupported SOCKS5 address type: 0x%02x", respHeader[3])
	}

	dummyBuf := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, dummyBuf); err != nil {
		return fmt.Errorf("failed to read SOCKS5 bound address: %w", err)
	}

	return nil
}

// handshake negotiates authentication with the SOCKS5 proxy
func (s *SOCKS5Dialer) handshake(conn net.Conn) error {
	// Methods supported
	methods := []byte{socksAuthNone}
	if s.Username != "" || s.Password != "" {
		methods = append(methods, socksAuthUserPass)
	}

	req := []byte{socksVersion5, byte(len(methods))}
	req = append(req, methods...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send SOCKS5 greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 greeting response: %w", err)
	}

	if resp[0] != socksVersion5 {
		return fmt.Errorf("unsupported SOCKS version: 0x%02x", resp[0])
	}

	switch resp[1] {
	case socksAuthNone:
		return nil
	case socksAuthUserPass:
		return s.authenticateUserPass(conn)
	case socksAuthNoAccept:
		return errors.New("SOCKS5 proxy rejected authentication methods")
	default:
		return fmt.Errorf("unsupported SOCKS5 auth method: 0x%02x", resp[1])
	}
}

// authenticateUserPass executes RFC 1929 username/password subnegotiation
func (s *SOCKS5Dialer) authenticateUserPass(conn net.Conn) error {
	// RFC 1929: [0x01, ulen, uname..., plen, passwd...]
	uLen := len(s.Username)
	pLen := len(s.Password)

	if uLen > 255 || pLen > 255 {
		return errors.New("SOCKS5 username or password exceeds maximum length of 255 bytes")
	}

	buf := make([]byte, 0, 3+uLen+pLen)
	buf = append(buf, 0x01, byte(uLen))
	buf = append(buf, []byte(s.Username)...)
	buf = append(buf, byte(pLen))
	buf = append(buf, []byte(s.Password)...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to send SOCKS5 RFC 1929 auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 RFC 1929 auth response: %w", err)
	}

	if resp[0] != 0x01 {
		return fmt.Errorf("invalid SOCKS5 auth subnegotiation version: 0x%02x", resp[0])
	}

	if resp[1] != 0x00 {
		return errors.New("SOCKS5 authentication failed: invalid username or password")
	}

	return nil
}

// connect issues the CONNECT command for a destination address (IP or Domain)
func (s *SOCKS5Dialer) connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid destination target %s: %w", target, err)
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid destination port %s: %w", portStr, err)
	}

	req := []byte{socksVersion5, socksCmdConnect, 0x00}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		req = append(req, socksAtypIPv4)
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = append(req, socksAtypIPv6)
		req = append(req, ip6...)
	} else {
		// Domain name fallback
		if len(host) > 255 {
			return errors.New("destination domain name exceeds 255 bytes")
		}
		req = append(req, socksAtypDomain, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	req = append(req, byte(portNum>>8), byte(portNum&0xFF))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send SOCKS5 CONNECT command: %w", err)
	}

	// Read reply header: VER, REP, RSV, ATYP
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return fmt.Errorf("failed to read SOCKS5 CONNECT response header: %w", err)
	}

	if respHeader[0] != socksVersion5 {
		return fmt.Errorf("invalid SOCKS5 response version: 0x%02x", respHeader[0])
	}

	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 server returned connect error code: 0x%02x (%s)", respHeader[1], socksErrorString(respHeader[1]))
	}

	// Drain bound address field in reply
	var addrLen int
	switch respHeader[3] {
	case socksAtypIPv4:
		addrLen = 4
	case socksAtypIPv6:
		addrLen = 16
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		addrLen = int(lenBuf[0])
	default:
		return fmt.Errorf("unsupported SOCKS5 address type in response: 0x%02x", respHeader[3])
	}

	dummyBuf := make([]byte, addrLen+2) // address + 2 bytes port
	if _, err := io.ReadFull(conn, dummyBuf); err != nil {
		return fmt.Errorf("failed to read SOCKS5 bound address: %w", err)
	}

	return nil
}

// DialUDP requests UDP Associate through the SOCKS5 proxy
func (s *SOCKS5Dialer) DialUDP(network, address string) (net.PacketConn, net.Addr, error) {
	// Connect to SOCKS5 server for control connection
	var d net.Dialer
	d.Timeout = s.Timeout
	ctrlConn, err := d.Dial("tcp", s.ProxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect SOCKS5 for UDP associate: %w", err)
	}

	if err := s.handshake(ctrlConn); err != nil {
		ctrlConn.Close()
		return nil, nil, err
	}

	// UDP ASSOCIATE command: 05 03 00 01 00 00 00 00 00 00
	req := []byte{socksVersion5, socksCmdUDPAssociate, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := ctrlConn.Write(req); err != nil {
		ctrlConn.Close()
		return nil, nil, fmt.Errorf("failed to request SOCKS5 UDP associate: %w", err)
	}

	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(ctrlConn, respHeader); err != nil {
		ctrlConn.Close()
		return nil, nil, fmt.Errorf("failed to read UDP associate response: %w", err)
	}

	if respHeader[1] != 0x00 {
		ctrlConn.Close()
		return nil, nil, fmt.Errorf("SOCKS5 UDP associate rejected with error 0x%02x", respHeader[1])
	}

	var relayIP net.IP
	switch respHeader[3] {
	case socksAtypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(ctrlConn, ipBuf); err != nil {
			ctrlConn.Close()
			return nil, nil, err
		}
		relayIP = net.IP(ipBuf)
	case socksAtypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(ctrlConn, ipBuf); err != nil {
			ctrlConn.Close()
			return nil, nil, err
		}
		relayIP = net.IP(ipBuf)
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(ctrlConn, lenBuf); err != nil {
			ctrlConn.Close()
			return nil, nil, err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(ctrlConn, domainBuf); err != nil {
			ctrlConn.Close()
			return nil, nil, err
		}
		ips, err := net.LookupIP(string(domainBuf))
		if err != nil || len(ips) == 0 {
			ctrlConn.Close()
			return nil, nil, fmt.Errorf("failed to resolve SOCKS5 UDP relay domain: %w", err)
		}
		relayIP = ips[0]
	default:
		ctrlConn.Close()
		return nil, nil, fmt.Errorf("unsupported ATYP in UDP associate: 0x%02x", respHeader[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(ctrlConn, portBuf); err != nil {
		ctrlConn.Close()
		return nil, nil, err
	}
	relayPort := int(portBuf[0])<<8 | int(portBuf[1])

	// If relay IP is 0.0.0.0, use the proxy server IP
	if relayIP.IsUnspecified() {
		pHost, _, _ := net.SplitHostPort(s.ProxyAddr)
		resolvedIPs, err := net.LookupIP(pHost)
		if err == nil && len(resolvedIPs) > 0 {
			relayIP = resolvedIPs[0]
		}
	}

	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	localPacketConn, err := net.ListenPacket("udp", "")
	if err != nil {
		ctrlConn.Close()
		return nil, nil, fmt.Errorf("failed to create local UDP socket: %w", err)
	}

	socksPacketConn := &SOCKS5PacketConn{
		PacketConn: localPacketConn,
		ctrlConn:   ctrlConn,
		relayAddr:  relayAddr,
	}

	return socksPacketConn, relayAddr, nil
}

// SOCKS5PacketConn wraps UDP packet conn and encapsulates/decapsulates SOCKS5 UDP headers
type SOCKS5PacketConn struct {
	net.PacketConn
	ctrlConn  net.Conn
	relayAddr *net.UDPAddr
}

func (c *SOCKS5PacketConn) Close() error {
	_ = c.ctrlConn.Close()
	return c.PacketConn.Close()
}

// WrapUDPPacket prepends SOCKS5 UDP header (RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT)
func WrapUDPPacket(targetHost string, targetPort int, payload []byte) ([]byte, error) {
	buf := make([]byte, 0, 10+len(targetHost)+len(payload))
	buf = append(buf, 0x00, 0x00, 0x00) // RSV (2 bytes) + FRAG (0x00)

	ip := net.ParseIP(targetHost)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, socksAtypIPv4)
		buf = append(buf, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		buf = append(buf, socksAtypIPv6)
		buf = append(buf, ip6...)
	} else {
		buf = append(buf, socksAtypDomain, byte(len(targetHost)))
		buf = append(buf, []byte(targetHost)...)
	}

	buf = append(buf, byte(targetPort>>8), byte(targetPort&0xFF))
	buf = append(buf, payload...)
	return buf, nil
}

// UnwrapUDPPacket removes SOCKS5 UDP header and extracts original payload
func UnwrapUDPPacket(data []byte) (payload []byte, srcAddr string, err error) {
	if len(data) < 10 {
		return nil, "", errors.New("UDP payload too short for SOCKS5 header")
	}

	// data[0], data[1] = RSV, data[2] = FRAG
	atyp := data[3]
	offset := 4
	var host string

	switch atyp {
	case socksAtypIPv4:
		if len(data) < offset+4+2 {
			return nil, "", errors.New("truncated IPv4 UDP header")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case socksAtypIPv6:
		if len(data) < offset+16+2 {
			return nil, "", errors.New("truncated IPv6 UDP header")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	case socksAtypDomain:
		dLen := int(data[offset])
		offset++
		if len(data) < offset+dLen+2 {
			return nil, "", errors.New("truncated domain UDP header")
		}
		host = string(data[offset : offset+dLen])
		offset += dLen
	default:
		return nil, "", fmt.Errorf("unknown ATYP in UDP header: 0x%02x", atyp)
	}

	port := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	return data[offset:], net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func socksErrorString(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error code 0x%02x", code)
	}
}
