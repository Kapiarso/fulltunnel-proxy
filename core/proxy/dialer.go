package proxy

import (
	"context"
	"net"
	"time"
)

// Dialer is the interface for outbound proxy connections
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	DialUDP(network, address string) (net.PacketConn, net.Addr, error)
	Protocol() string
	TargetServer() string
}

// BaseDialer provides direct TCP/UDP fallback
type DirectDialer struct {
	Timeout time.Duration
}

func NewDirectDialer() *DirectDialer {
	return &DirectDialer{
		Timeout: 10 * time.Second,
	}
}

func (d *DirectDialer) Dial(network, address string) (net.Conn, error) {
	return net.DialTimeout(network, address, d.Timeout)
}

func (d *DirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var netDialer net.Dialer
	return netDialer.DialContext(ctx, network, address)
}

func (d *DirectDialer) DialUDP(network, address string) (net.PacketConn, net.Addr, error) {
	dstAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenPacket("udp", "")
	return conn, dstAddr, err
}

func (d *DirectDialer) Protocol() string {
	return "direct"
}

func (d *DirectDialer) TargetServer() string {
	return "direct"
}
