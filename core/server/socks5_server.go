package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"socks_connector/core/logger"
)

// SOCKS5Server is a built-in enterprise high-throughput SOCKS5 proxy server.
type SOCKS5Server struct {
	ListenAddr   string // e.g. "0.0.0.0:1080"
	OutboundIP   string // e.g. "192.168.18.32" (binds outbound traffic to physical NIC to prevent any loop)
	Username     string
	Password     string
	listener     net.Listener
	closed       bool
	mu           sync.Mutex
	activeConns  sync.WaitGroup
	bufferPool   sync.Pool
}

// NewSOCKS5Server creates a new SOCKS5 server instance.
func NewSOCKS5Server(listenAddr, outboundIP, username, password string) *SOCKS5Server {
	return &SOCKS5Server{
		ListenAddr: listenAddr,
		OutboundIP: outboundIP,
		Username:   username,
		Password:   password,
		bufferPool: sync.Pool{
			New: func() any {
				b := make([]byte, 64*1024)
				return &b
			},
		},
	}
}

// Start begins listening and serving SOCKS5 proxy connections.
func (s *SOCKS5Server) Start() error {
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return errors.New("SOCKS5 server already running")
	}

	l, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to bind SOCKS5 server on %s: %w", s.ListenAddr, err)
	}
	s.listener = l
	s.closed = false
	s.mu.Unlock()

	logger.Success("[SOCKS5 SERVER] Running on %s (Outbound Bind: %s)", s.ListenAddr, s.OutboundIP)

	go s.acceptLoop(l)
	return nil
}

// Stop gracefully stops the SOCKS5 server.
func (s *SOCKS5Server) Stop() error {
	s.mu.Lock()
	if s.listener == nil {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	_ = s.listener.Close()
	s.listener = nil
	s.mu.Unlock()

	s.activeConns.Wait()
	logger.Info("[SOCKS5 SERVER] Stopped successfully.")
	return nil
}

func (s *SOCKS5Server) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		s.activeConns.Add(1)
		go func(c net.Conn) {
			defer s.activeConns.Done()
			defer c.Close()
			s.handleClient(c)
		}(conn)
	}
}

func (s *SOCKS5Server) handleClient(client net.Conn) {
	// TCP socket optimizations
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(2 << 20)
		_ = tc.SetWriteBuffer(2 << 20)
	}

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Handshake: Version + Auth Methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return // Not SOCKS5
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// Determine Auth Method
	authRequired := s.Username != ""
	selectedMethod := byte(0xFF) // No acceptable method

	for _, m := range methods {
		if authRequired && m == 0x02 { // Username/Password
			selectedMethod = 0x02
			break
		}
		if !authRequired && m == 0x00 { // No auth
			selectedMethod = 0x00
			break
		}
	}

	if selectedMethod == 0xFF {
		_, _ = client.Write([]byte{0x05, 0xFF})
		return
	}

	if _, err := client.Write([]byte{0x05, selectedMethod}); err != nil {
		return
	}

	// 2. Perform Auth if required
	if selectedMethod == 0x02 {
		authVer := make([]byte, 1)
		if _, err := io.ReadFull(client, authVer); err != nil || authVer[0] != 0x01 {
			return
		}

		uLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, uLenBuf); err != nil {
			return
		}
		userBuf := make([]byte, int(uLenBuf[0]))
		if _, err := io.ReadFull(client, userBuf); err != nil {
			return
		}

		pLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, pLenBuf); err != nil {
			return
		}
		passBuf := make([]byte, int(pLenBuf[0]))
		if _, err := io.ReadFull(client, passBuf); err != nil {
			return
		}

		if string(userBuf) != s.Username || string(passBuf) != s.Password {
			_, _ = client.Write([]byte{0x01, 0x01}) // Auth Failed
			return
		}
		if _, err := client.Write([]byte{0x01, 0x00}); err != nil { // Auth OK
			return
		}
	}

	// 3. Request details: CMD, ATYP, DST.ADDR, DST.PORT
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHead); err != nil {
		return
	}
	if reqHead[0] != 0x05 {
		return
	}

	cmd := reqHead[1]
	atyp := reqHead[3]

	var targetHost string
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(client, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	case 0x03: // Domain
		dLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, dLenBuf); err != nil {
			return
		}
		domBuf := make([]byte, int(dLenBuf[0]))
		if _, err := io.ReadFull(client, domBuf); err != nil {
			return
		}
		targetHost = string(domBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(client, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)

	// We only support CONNECT command (0x01)
	if cmd != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	// 4. Connect to upstream target with optional physical NIC binding
	var dialer net.Dialer
	dialer.Timeout = 10 * time.Second
	if s.OutboundIP != "" {
		localTCPAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.OutboundIP, "0"))
		if err == nil {
			dialer.LocalAddr = localTCPAddr
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	remote, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer remote.Close()

	if tc, ok := remote.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(2 << 20)
		_ = tc.SetWriteBuffer(2 << 20)
	}

	// Success response
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Clear deadlines for full-duplex high-throughput proxy streaming
	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})

	// 5. Bidirectional zero-allocation pipe
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		bufPtr := s.bufferPool.Get().(*[]byte)
		defer s.bufferPool.Put(bufPtr)
		_, _ = io.CopyBuffer(dst, src, *bufPtr)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	go pipe(remote, client)
	go pipe(client, remote)

	wg.Wait()
}
