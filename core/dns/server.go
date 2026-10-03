package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"socks_connector/core/proxy"
)

// DNS query types
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypePTR   uint16 = 12
	TypeAAAA  uint16 = 28
)

// Server is the zero-leak local DNS server
var PrefetchDNSHook func(domain string)

func prefetchDNS(domain string) {
	if PrefetchDNSHook != nil {
		PrefetchDNSHook(domain)
	}
}

type Server struct {
	listenAddr string
	fakeIPPool *FakeIPPool
	dialer     proxy.Dialer
	udpConn    net.PacketConn
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewServer creates a new local DNS server
func NewServer(listenAddr string, pool *FakeIPPool, dialer proxy.Dialer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		listenAddr: listenAddr,
		fakeIPPool: pool,
		dialer:     dialer,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start launches optional local UDP DNS listener (best-effort)
func (s *Server) Start() error {
	uConn, err := net.ListenPacket("udp", s.listenAddr)
	if err != nil {
		// Non-fatal if userspace interception is active
		return nil
	}
	s.udpConn = uConn

	s.wg.Add(1)
	go s.serveUDP()

	return nil
}

// Stop terminates the DNS server
func (s *Server) Stop() {
	s.cancel()
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, clientAddr, err := s.udpConn.ReadFrom(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		reqData := make([]byte, n)
		copy(reqData, buf[:n])

		go func(data []byte, addr net.Addr) {
			resp, err := HandleDNSQuery(data, s.fakeIPPool)
			if err == nil && len(resp) > 0 {
				_, _ = s.udpConn.WriteTo(resp, addr)
			}
		}(reqData, clientAddr)
	}
}

// HandleDNSQuery parses DNS message and generates Fake-IP response directly in memory
func HandleDNSQuery(msg []byte, fakeIPPool *FakeIPPool) ([]byte, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS query too short")
	}

	txID := binary.BigEndian.Uint16(msg[0:2])
	qdCount := binary.BigEndian.Uint16(msg[4:6])

	if qdCount == 0 {
		return nil, errors.New("no question in DNS query")
	}

	domain, qType, qClass, offset, err := parseQuestion(msg, 12)
	if err != nil {
		return nil, err
	}

	_ = qClass
	_ = offset

	// For IPv4 A queries, return Fake-IP immediately & pre-fetch upstream DNS
	if qType == TypeA {
		fakeIP := fakeIPPool.Allocate(domain)
		go prefetchDNS(domain)
		return buildAResponse(txID, msg[12:offset], fakeIP), nil
	}

	// For AAAA or PTR queries, synthesize an empty success response (NODATA)
	// to force apps to use IPv4 Fake-IP
	return buildEmptyResponse(txID, msg[12:offset]), nil
}

func parseQuestion(msg []byte, offset int) (domain string, qType uint16, qClass uint16, nextOffset int, err error) {
	var domainParts []string

	for offset < len(msg) {
		length := int(msg[offset])
		offset++
		if length == 0 {
			break
		}
		if offset+length > len(msg) {
			return "", 0, 0, 0, errors.New("malformed domain name in query")
		}
		domainParts = append(domainParts, string(msg[offset:offset+length]))
		offset += length
	}

	if offset+4 > len(msg) {
		return "", 0, 0, 0, errors.New("malformed question header")
	}

	domain = strings.Join(domainParts, ".")
	qType = binary.BigEndian.Uint16(msg[offset : offset+2])
	qClass = binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	nextOffset = offset + 4

	return domain, qType, qClass, nextOffset, nil
}

func buildAResponse(txID uint16, questionData []byte, ip net.IP) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		ip4 = net.IPv4(198, 18, 0, 1).To4()
	}

	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], txID)
	// Flags: Standard query response, No error, Authoritative, Recursion Available
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT = 1
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	// Append Question section
	resp = append(resp, questionData...)

	// Answer Section: Name Pointer (0xc00c -> offset 12 in message)
	resp = append(resp, 0xc0, 0x0c)
	// Type A (0x0001)
	resp = append(resp, 0x00, 0x01)
	// Class IN (0x0001)
	resp = append(resp, 0x00, 0x01)
	// TTL: 60 seconds (efficient caching, instant web refresh)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
	// RDLENGTH: 4 bytes
	resp = append(resp, 0x00, 0x04)
	// RDATA: IPv4 bytes
	resp = append(resp, ip4...)

	return resp
}

func buildEmptyResponse(txID uint16, questionData []byte) []byte {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], txID)
	// Flags: Response, No error, 0 Answers
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1
	binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT = 0
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	resp = append(resp, questionData...)
	return resp
}

// Safe check
var _ = fmt.Sprintf
var _ = time.Now
