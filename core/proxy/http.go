package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPDialer implements HTTP/HTTPS CONNECT proxy client with authentication
type HTTPDialer struct {
	ProxyAddr string
	IsTLS     bool
	Username  string
	Password  string
	Timeout   time.Duration
}

// NewHTTPDialer creates an HTTP or HTTPS CONNECT proxy dialer
func NewHTTPDialer(host string, port int, isTLS bool, username, password string) *HTTPDialer {
	return &HTTPDialer{
		ProxyAddr: net.JoinHostPort(host, strconv.Itoa(port)),
		IsTLS:     isTLS,
		Username:  username,
		Password:  password,
		Timeout:   10 * time.Second,
	}
}

func (h *HTTPDialer) Protocol() string {
	if h.IsTLS {
		return "https"
	}
	return "http"
}

func (h *HTTPDialer) TargetServer() string {
	return h.ProxyAddr
}

func (h *HTTPDialer) Dial(network, address string) (net.Conn, error) {
	return h.DialContext(context.Background(), network, address)
}

func (h *HTTPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var rawConn net.Conn
	var err error

	var d net.Dialer
	d.Timeout = h.Timeout

	if h.IsTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         strings.Split(h.ProxyAddr, ":")[0],
		}
		rawConn, err = tls.DialWithDialer(&d, "tcp", h.ProxyAddr, tlsConfig)
	} else {
		rawConn, err = d.DialContext(ctx, "tcp", h.ProxyAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy %s: %w", h.ProxyAddr, err)
	}

	// Prepare CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)

	// Add authentication header if provided
	if h.Username != "" || h.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(h.Username + ":" + h.Password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	connectReq += "Proxy-Connection: Keep-Alive\r\nUser-Agent: SecureTunnel/1.0\r\n\r\n"

	if _, err := rawConn.Write([]byte(connectReq)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read HTTP response
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to read HTTP CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		rawConn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed with status code: %d %s", resp.StatusCode, resp.Status)
	}

	return rawConn, nil
}

func (h *HTTPDialer) DialUDP(network, address string) (net.PacketConn, net.Addr, error) {
	return nil, nil, errors.New("HTTP CONNECT proxy does not support UDP relay (use SOCKS5 for full UDP support)")
}
