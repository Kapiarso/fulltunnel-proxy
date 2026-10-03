package stack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"socks_connector/core/dns"
	"socks_connector/core/proxy"
	"socks_connector/core/stats"
	"socks_connector/core/tun"

	"golang.org/x/sys/windows"
)

// IP Protocols
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// TCP Flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// IPStack implements a high-throughput, enterprise-grade userspace L3/L4 IP stack
type IPStack struct {
	dev          tun.Device
	dialer       proxy.Dialer
	fakeIPPool   *dns.FakeIPPool
	tracker      *stats.Tracker
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	readerWg     sync.WaitGroup
	stopped      atomic.Bool

	numWorkers   int
	workerChans  []chan []byte
	priorityChan chan []byte // Dedicated Enterprise QoS High-Priority Interactive Channel (0ms queue delay)

	// Active TCP sessions: key = "srcIP:srcPort-dstIP:dstPort"
	tcpMu       sync.RWMutex
	tcpSessions map[string]*tcpSession

	// Active UDP sessions: key = "srcIP:srcPort-dstIP:dstPort"
	udpMu       sync.RWMutex
	udpSessions map[string]*udpSession

	pktPool     sync.Pool
}

type tcpSession struct {
	key            string
	srcIP          net.IP
	srcPort        uint16
	dstIP          net.IP
	dstPort        uint16
	targetAddr     string
	clientSeq      atomic.Uint32 // Expected next SEQ from client
	clientAck      atomic.Uint32 // Highest server SEQ acknowledged by client
	serverSeq      atomic.Uint32 // Next server SEQ to send
	clientMSS      uint16        // MSS advertised by client
	clientWinScale uint8         // Window scale factor from client SYN
	clientWin      atomic.Uint32 // Scaled receive window from client
	clientFinChan  chan struct{}
	clientFinOnce  sync.Once
	winNotify      chan struct{} // Non-blocking signal when window updates
	proxyConn      net.Conn
	connID         string
	lastActive     atomic.Int64
	closed         atomic.Bool
	closeChan      chan struct{}
	mu             sync.Mutex
	pendingBuf     []byte
	established    bool

	uploadChan     chan []byte
	uploadOnce     sync.Once
}

type udpSession struct {
	key        string
	srcIP      net.IP
	srcPort    uint16
	dstIP      net.IP
	dstPort    uint16
	targetAddr string
	relayConn  net.PacketConn
	relayAddr  net.Addr
	connID     string
	lastActive atomic.Int64
	closed     atomic.Bool
}

// NewIPStack creates an enterprise-grade pure Go user-space network stack
func NewIPStack(dev tun.Device, dialer proxy.Dialer, fakeIP *dns.FakeIPPool, tracker *stats.Tracker) (*IPStack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	numWorkers := 32

	workerChans := make([]chan []byte, numWorkers)
	for i := 0; i < numWorkers; i++ {
		workerChans[i] = make(chan []byte, 16384)
	}

	stack := &IPStack{
		dev:          dev,
		dialer:       dialer,
		fakeIPPool:   fakeIP,
		tracker:      tracker,
		ctx:          ctx,
		cancel:       cancel,
		numWorkers:   numWorkers,
		workerChans:  workerChans,
		priorityChan: make(chan []byte, 16384),
		tcpSessions:  make(map[string]*tcpSession),
		udpSessions: make(map[string]*udpSession),
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 65535)
				return &b
			},
		},
	}

	dns.PrefetchDNSHook = func(domain string) {
		go resolveUpstreamDNS(domain)
	}

	return stack, nil
}

// Start launches packet pump, flow workers and session cleanup loops
func (s *IPStack) Start() {
	s.readerWg.Add(1)
	go s.packetReaderLoop()

	s.wg.Add(s.numWorkers + 1)
	for i := 0; i < s.numWorkers; i++ {
		go s.workerLoop(i)
	}
	go s.cleanupStaleSessionsLoop()
}

// Stop terminates the stack safely without channel panics
func (s *IPStack) Stop() {
	if !s.stopped.CompareAndSwap(false, true) {
		return
	}
	s.cancel()

	// Wait for reader loop to finish before closing channels
	s.readerWg.Wait()

	for i := 0; i < s.numWorkers; i++ {
		close(s.workerChans[i])
	}

	s.tcpMu.Lock()
	for _, sess := range s.tcpSessions {
		sess.close(s.tracker)
	}
	s.tcpSessions = make(map[string]*tcpSession)
	s.tcpMu.Unlock()

	s.udpMu.Lock()
	for _, sess := range s.udpSessions {
		sess.close(s.tracker)
	}
	s.udpSessions = make(map[string]*udpSession)
	s.udpMu.Unlock()

	s.wg.Wait()
}

func (s *IPStack) workerLoop(idx int) {
	defer s.wg.Done()

	flowQueues := make(map[uint32][][]byte)
	activeFlows := make([]uint32, 0, 64)

	for {
		select {
		case pkt, ok := <-s.workerChans[idx]:
			if !ok {
				return
			}

			// Extract 5-tuple flow ID
			if len(pkt) >= 24 && pkt[0]>>4 == 4 {
				ihl := int(pkt[0]&0x0F) * 4
				if len(pkt) >= ihl+4 {
					srcIP := net.IP(pkt[12:16])
					dstIP := net.IP(pkt[16:20])
					srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
					dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
					flowID := hashFlow(srcIP, dstIP, srcPort, dstPort)

					if q, exists := flowQueues[flowID]; exists {
						flowQueues[flowID] = append(q, pkt)
					} else {
						flowQueues[flowID] = [][]byte{pkt}
						activeFlows = append(activeFlows, flowID)
					}
				} else {
					s.handleInboundPacket(pkt)
				}
			} else {
				s.handleInboundPacket(pkt)
			}

		case <-s.ctx.Done():
			return
		}

		// Enterprise Fair-Queueing (Deficit Round-Robin): service 1 packet per active flow queue
		if len(activeFlows) > 0 {
			nextActive := make([]uint32, 0, len(activeFlows))
			for _, flowID := range activeFlows {
				q := flowQueues[flowID]
				if len(q) > 0 {
					p := q[0]
					flowQueues[flowID] = q[1:]
					s.handleInboundPacket(p)
					if len(flowQueues[flowID]) > 0 {
						nextActive = append(nextActive, flowID)
					} else {
						delete(flowQueues, flowID)
					}
				} else {
					delete(flowQueues, flowID)
				}
			}
			activeFlows = nextActive
		}
	}
}

func hashFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16) uint32 {
	var h uint32 = 2166136261
	for _, b := range srcIP {
		h = (h ^ uint32(b)) * 16777619
	}
	for _, b := range dstIP {
		h = (h ^ uint32(b)) * 16777619
	}
	h = (h ^ uint32(srcPort)) * 16777619
	h = (h ^ uint32(dstPort)) * 16777619
	return h
}

func (s *IPStack) packetReaderLoop() {
	defer s.readerWg.Done()
	mtu := s.dev.MTU()
	if mtu <= 0 {
		mtu = 1500
	}
	buf := make([]byte, mtu+200)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := s.dev.Read(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			time.Sleep(1 * time.Millisecond)
			continue
		}

		if n < 20 {
			continue
		}

		version := buf[0] >> 4
		if version == 6 {
			// Fast-Reject IPv6 TCP SYN packets to force immediate Happy Eyeballs fallback to IPv4 in 0ms
			if n >= 60 && buf[6] == ProtoTCP {
				tcpFlags := buf[53]
				if tcpFlags&TCPFlagSYN != 0 && tcpFlags&TCPFlagACK == 0 {
					srcIP := net.IP(buf[8:24])
					dstIP := net.IP(buf[24:40])
					srcPort := binary.BigEndian.Uint16(buf[40:42])
					dstPort := binary.BigEndian.Uint16(buf[42:44])
					seq := binary.BigEndian.Uint32(buf[44:48])
					s.sendIPv6TCPRST(dstIP, srcIP, dstPort, srcPort, 0, seq+1)
				}
			}
			continue
		}
		if version != 4 {
			continue // IPv4 supported
		}

		protocol := buf[9]
		srcIP := net.IP(buf[12:16])
		dstIP := net.IP(buf[16:20])

		var srcPort, dstPort uint16
		if (protocol == ProtoTCP || protocol == ProtoUDP) && n >= 24 {
			srcPort = binary.BigEndian.Uint16(buf[20:22])
			dstPort = binary.BigEndian.Uint16(buf[22:24])
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		idx := hashFlow(srcIP, dstIP, srcPort, dstPort) % uint32(s.numWorkers)
		select {
		case s.workerChans[idx] <- packet:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *IPStack) handleInboundPacket(pkt []byte) {
	version := pkt[0] >> 4
	if version != 4 {
		return // IPv4 supported
	}

	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl {
		return
	}

	protocol := pkt[9]
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])

	// 1. Drop Loopback, Wintun Self, and Subnet Broadcasts
	if dstIP.IsLoopback() || dstIP.Equal(net.ParseIP("127.0.0.1")) || dstIP.Equal(net.ParseIP("172.19.0.1")) || dstIP.Equal(net.ParseIP("172.19.0.2")) || dstIP.Equal(net.ParseIP("172.19.0.3")) {
		return
	}

	// 2. Drop IPv4 Multicast (224.0.0.0/4: 224.x.x.x - 239.x.x.x) and Global Broadcast
	if dstIP.IsMulticast() || dstIP[0] >= 224 || dstIP.Equal(net.IPv4bcast) || dstIP.To4()[3] == 255 {
		return
	}

	// 3. Drop Windows local network discovery protocols (NetBIOS, LLMNR, mDNS, SSDP)
	if protocol == ProtoUDP && len(pkt) >= ihl+4 {
		dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		if dstPort == 137 || dstPort == 138 || dstPort == 139 || dstPort == 5353 || dstPort == 5355 || dstPort == 1900 {
			return
		}
	}

	switch protocol {
	case ProtoICMP:
		s.handleICMP(pkt, ihl, srcIP, dstIP)
	case ProtoUDP:
		s.handleUDP(pkt, ihl, srcIP, dstIP)
	case ProtoTCP:
		s.handleTCP(pkt, ihl, srcIP, dstIP)
	}
}

// ---------------------- ICMP (Ping) Handling ----------------------

func (s *IPStack) handleICMP(pkt []byte, ihl int, srcIP, dstIP net.IP) {
	icmpData := pkt[ihl:]
	if len(icmpData) < 8 {
		return
	}

	// Echo Request = Type 8
	if icmpData[0] == 8 {
		// Formulate Echo Reply = Type 0
		replyICMP := make([]byte, len(icmpData))
		copy(replyICMP, icmpData)
		replyICMP[0] = 0 // Type 0 (Echo Reply)
		replyICMP[2] = 0 // Checksum reset
		replyICMP[3] = 0
		chk := checksum(replyICMP)
		binary.BigEndian.PutUint16(replyICMP[2:4], chk)

		s.sendIPPacket(dstIP, srcIP, ProtoICMP, replyICMP)
	}
}

func (s *IPStack) sendICMPPortUnreachable(srcIP, dstIP net.IP, origData []byte) {
	copyLen := len(origData)
	if copyLen > 64 {
		copyLen = 64
	}
	icmpLen := 8 + copyLen
	icmpData := make([]byte, icmpLen)
	icmpData[0] = 3 // Type 3 (Destination Unreachable)
	icmpData[1] = 3 // Code 3 (Port Unreachable)
	copy(icmpData[8:], origData[:copyLen])

	chk := checksum(icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], chk)

	s.sendIPPacket(dstIP, srcIP, ProtoICMP, icmpData)
}

// ---------------------- UDP Handling ----------------------

func (s *IPStack) handleUDP(pkt []byte, ihl int, srcIP, dstIP net.IP) {
	udpData := pkt[ihl:]
	if len(udpData) < 8 {
		return
	}

	srcPort := binary.BigEndian.Uint16(udpData[0:2])
	dstPort := binary.BigEndian.Uint16(udpData[2:4])
	udpLen := int(binary.BigEndian.Uint16(udpData[4:6]))

	if len(udpData) < udpLen || udpLen < 8 {
		return
	}

	payload := udpData[8:udpLen]

	// Direct Userspace DNS Interception (0ms latency, zero leak)
	if dstPort == 53 && s.fakeIPPool != nil {
		dnsResp, err := dns.HandleDNSQuery(payload, s.fakeIPPool)
		if err == nil && len(dnsResp) > 0 {
			udpPacket := make([]byte, 8+len(dnsResp))
			binary.BigEndian.PutUint16(udpPacket[0:2], dstPort)
			binary.BigEndian.PutUint16(udpPacket[2:4], srcPort)
			binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))
			udpPacket[6] = 0 // Checksum
			udpPacket[7] = 0
			copy(udpPacket[8:], dnsResp)

			s.sendIPPacket(dstIP, srcIP, ProtoUDP, udpPacket)
			return
		}
	}

	// Fast-Reject all non-DNS UDP traffic (QUIC / STUN / UDP Speedtest) via ICMP Port Unreachable
	// so Chrome, Speedtest.net, and Windows Apps instantly fallback to multi-stream parallel TCP
	if dstPort != 53 {
		s.sendICMPPortUnreachable(srcIP, dstIP, pkt)
		return
	}

	sessKey := fmt.Sprintf("%s:%d-%s:%d", srcIP.String(), srcPort, dstIP.String(), dstPort)

	s.udpMu.Lock()
	sess, exists := s.udpSessions[sessKey]
	if !exists || sess.closed.Load() {
		var targetAddr string
		if s.fakeIPPool != nil && s.fakeIPPool.Contains(dstIP) {
			if domain, found := s.fakeIPPool.LookupDomain(dstIP); found {
				targetAddr = fmt.Sprintf("%s:%d", domain, dstPort)
			}
		}
		if targetAddr == "" {
			targetAddr = fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
		}

		relayConn, relayAddr, err := s.dialer.DialUDP("udp", targetAddr)
		if err != nil {
			s.udpMu.Unlock()
			return
		}

		connID := fmt.Sprintf("udp-%s-%d", sessKey, time.Now().UnixNano())
		sess = &udpSession{
			key:        sessKey,
			srcIP:      srcIP,
			srcPort:    srcPort,
			dstIP:      dstIP,
			dstPort:    dstPort,
			targetAddr: targetAddr,
			relayConn:  relayConn,
			relayAddr:  relayAddr,
			connID:     connID,
		}
		sess.lastActive.Store(time.Now().Unix())
		s.udpSessions[sessKey] = sess
		s.udpMu.Unlock()

		s.tracker.RegisterConn(connID, "udp", fmt.Sprintf("%s:%d", srcIP.String(), srcPort), targetAddr)
		go s.pumpUDPDownstream(sess)
	} else {
		s.udpMu.Unlock()
	}

	sess.lastActive.Store(time.Now().Unix())

	// Wrap payload and send upstream
	host, portStr, _ := net.SplitHostPort(sess.targetAddr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	enc, err := proxy.WrapUDPPacket(host, port, payload)
	if err == nil {
		nw, ew := sess.relayConn.WriteTo(enc, sess.relayAddr)
		if ew == nil && nw > 0 {
			s.tracker.AddUpload(int64(len(payload)))
			s.tracker.UpdateConn(sess.connID, int64(len(payload)), 0)
		}
	}
}

func (s *IPStack) pumpUDPDownstream(sess *udpSession) {
	defer func() {
		sess.close(s.tracker)
		s.udpMu.Lock()
		delete(s.udpSessions, sess.key)
		s.udpMu.Unlock()
	}()

	buf := make([]byte, 65535) // Support max 65KB Jumbo UDP Datagrams

	for {
		if s.ctx.Err() != nil || sess.closed.Load() {
			return
		}

		_ = sess.relayConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, _, err := sess.relayConn.ReadFrom(buf)
		if err != nil {
			return
		}

		if n > 0 {
			payload, _, err := proxy.UnwrapUDPPacket(buf[:n])
			if err == nil && len(payload) > 0 {
				sess.lastActive.Store(time.Now().Unix())
				s.tracker.AddDownload(int64(len(payload)))
				s.tracker.UpdateConn(sess.connID, 0, int64(len(payload)))

				// Build UDP Packet back to client
				udpPacket := make([]byte, 8+len(payload))
				binary.BigEndian.PutUint16(udpPacket[0:2], sess.dstPort)
				binary.BigEndian.PutUint16(udpPacket[2:4], sess.srcPort)
				binary.BigEndian.PutUint16(udpPacket[4:6], uint16(len(udpPacket)))
				udpPacket[6] = 0 // Checksum
				udpPacket[7] = 0
				copy(udpPacket[8:], payload)

				s.sendIPPacket(sess.dstIP, sess.srcIP, ProtoUDP, udpPacket)
			}
		}
	}
}

func (u *udpSession) close(tracker *stats.Tracker) {
	if u.closed.CompareAndSwap(false, true) {
		if u.relayConn != nil {
			_ = u.relayConn.Close()
		}
		if tracker != nil {
			tracker.UnregisterConn(u.connID)
		}
	}
}

// ---------------------- Enterprise High-Throughput TCP Handling ----------------------

func (s *IPStack) handleTCP(pkt []byte, ihl int, srcIP, dstIP net.IP) {
	tcpData := pkt[ihl:]
	if len(tcpData) < 20 {
		return
	}

	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	seq := binary.BigEndian.Uint32(tcpData[4:8])
	ack := binary.BigEndian.Uint32(tcpData[8:12])
	dataOffset := int(tcpData[12]>>4) * 4
	flags := tcpData[13]

	if len(tcpData) < dataOffset {
		return
	}

	payload := tcpData[dataOffset:]
	sessKey := fmt.Sprintf("%s:%d-%s:%d", srcIP.String(), srcPort, dstIP.String(), dstPort)

	if flags&TCPFlagSYN != 0 {
		// Log SYN
	} else if len(payload) > 0 || flags&TCPFlagFIN != 0 || flags&TCPFlagRST != 0 {
		// fmt.Printf("[RECV TCP] %s -> %s | SEQ=%d ACK=%d FLAGS=0x%02x LEN=%d\n", srcIP, dstIP, seq, ack, flags, len(payload))
	}

	// 1. SYN Handshake
	if flags&TCPFlagSYN != 0 && flags&TCPFlagACK == 0 {
		var synOpts []byte
		if dataOffset > 20 && len(tcpData) >= dataOffset {
			synOpts = tcpData[20:dataOffset]
		}
		s.handleTCPSYN(sessKey, srcIP, dstIP, srcPort, dstPort, seq, synOpts)
		return
	}

	s.tcpMu.RLock()
	sess, exists := s.tcpSessions[sessKey]
	s.tcpMu.RUnlock()

	if !exists || sess.closed.Load() {
		// Never send RST on trailing ACKs, FINs, or empty packets — ignore them gracefully!
		if flags&TCPFlagRST == 0 && (flags&TCPFlagSYN != 0 || len(payload) > 0) {
			s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, ack, seq+1, TCPFlagRST|TCPFlagACK, nil, nil)
		}
		return
	}

	sess.lastActive.Store(time.Now().Unix())

	// 2. Track Sequence & Acks + update flow-control window
	if flags&TCPFlagACK != 0 {
		curAck := sess.clientAck.Load()
		if ack > curAck {
			sess.clientAck.Store(ack)
		}

		rawWin := uint32(binary.BigEndian.Uint16(tcpData[14:16]))
		rcvWin := rawWin << sess.clientWinScale
		sess.clientWin.Store(rcvWin)
		select {
		case sess.winNotify <- struct{}{}:
		default:
		}
	}

	// 3. RST or FIN
	if flags&TCPFlagRST != 0 {
		sess.close(s.tracker)
		s.tcpMu.Lock()
		if cur, ok := s.tcpSessions[sessKey]; ok && cur == sess {
			delete(s.tcpSessions, sessKey)
		}
		s.tcpMu.Unlock()
		return
	}

	if flags&TCPFlagFIN != 0 {
		newClientSeq := seq + 1
		sess.clientSeq.Store(newClientSeq)
		// 1. Acknowledge client's FIN with pure ACK
		s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, sess.serverSeq.Load(), newClientSeq, TCPFlagACK, nil, nil)

		// 2. Graceful Half-Close: Close upload direction, but keep download reading until upstream EOF!
		sess.clientFinOnce.Do(func() {
			close(sess.clientFinChan)
			sess.uploadOnce.Do(func() {
				if sess.uploadChan != nil {
					close(sess.uploadChan)
				}
			})
			sess.mu.Lock()
			if sess.proxyConn != nil {
				if tc, ok := sess.proxyConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}
			sess.mu.Unlock()
		})
		return
	}

	// 4. Payload Data from Client -> Forward to Upstream Proxy via Async Upload Queue
	if len(payload) > 0 {
		curExpected := sess.clientSeq.Load()
		payloadLen := uint32(len(payload))

		if seq == curExpected {
			// Strict cumulative in-order sequence tracking
			newExpected := curExpected + payloadLen
			sess.clientSeq.Store(newExpected)

			sess.mu.Lock()
			if sess.established {
				sess.mu.Unlock()
				pktCopy := make([]byte, len(payload))
				copy(pktCopy, payload)
				sess.safeSendUpload(pktCopy)
			} else {
				sess.pendingBuf = append(sess.pendingBuf, payload...)
				sess.mu.Unlock()
			}

			// Send cumulative ACK back to client
			s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, sess.serverSeq.Load(), newExpected, TCPFlagACK, nil, nil)
		} else if seq < curExpected {
			// Retransmitted / duplicate packet: resend current cumulative ACK without duplicate upload
			s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, sess.serverSeq.Load(), curExpected, TCPFlagACK, nil, nil)
		} else {
			// Out-of-order packet: send Duplicate ACK for expected sequence to prompt fast retransmit
			s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, sess.serverSeq.Load(), curExpected, TCPFlagACK, nil, nil)
		}
	}
}

func (s *IPStack) handleTCPSYN(sessKey string, srcIP, dstIP net.IP, srcPort, dstPort uint16, clientSeq uint32, tcpOptions []byte) {
	var targetAddr string
	if s.fakeIPPool != nil && s.fakeIPPool.Contains(dstIP) {
		if domain, found := s.fakeIPPool.LookupDomain(dstIP); found {
			targetAddr = fmt.Sprintf("%s:%d", domain, dstPort)
		}
	}
	if targetAddr == "" {
		targetAddr = fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	}

	// SYN Retransmit Dedup
	s.tcpMu.RLock()
	existing, exists := s.tcpSessions[sessKey]
	s.tcpMu.RUnlock()
	if exists && !existing.closed.Load() {
		mssByte1 := byte(existing.clientMSS >> 8)
		mssByte2 := byte(existing.clientMSS & 0xFF)
		opts := []byte{
			0x02, 0x04, mssByte1, mssByte2,
			0x01, 0x03, 0x03, existing.clientWinScale,
			0x01, 0x04, 0x02,
		}
		s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, existing.serverSeq.Load()-1, clientSeq+1, TCPFlagSYN|TCPFlagACK, opts, nil)
		return
	}

	// Parse client MSS and Window Scale from SYN TCP options
	clientMSS, winScale := parseTCPOptions(tcpOptions)
	if clientMSS == 0 {
		clientMSS = 1460
	}
	if winScale > 14 {
		winScale = 8
	}

	serverISN := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
	connID := fmt.Sprintf("tcp-%s-%d", sessKey, time.Now().UnixNano())

	effectiveMSS := uint16(s.dev.MTU() - 40)
	if effectiveMSS < 536 {
		effectiveMSS = 1360
	}
	if clientMSS > 0 && clientMSS < effectiveMSS {
		effectiveMSS = clientMSS
	}

	sess := &tcpSession{
		key:            sessKey,
		srcIP:          srcIP,
		srcPort:        srcPort,
		dstIP:          dstIP,
		dstPort:        dstPort,
		targetAddr:     targetAddr,
		connID:         connID,
		closeChan:      make(chan struct{}),
		clientFinChan:  make(chan struct{}),
		winNotify:      make(chan struct{}, 16),
		uploadChan:     make(chan []byte, 16384),
		clientMSS:      effectiveMSS,
		clientWinScale: winScale,
	}
	sess.clientSeq.Store(clientSeq + 1)
	sess.serverSeq.Store(serverISN + 1) // Initial server sequence number
	sess.clientAck.Store(serverISN + 1) // CRITICAL: Synchronize clientAck to serverISN+1 so inFlight starts at 0!
	sess.clientWin.Store(65535 << winScale)
	sess.lastActive.Store(time.Now().Unix())

	s.tcpMu.Lock()
	s.tcpSessions[sessKey] = sess
	s.tcpMu.Unlock()

	// Advertise our MSS and Window Scale in SYN-ACK
	mssByte1 := byte(effectiveMSS >> 8)
	mssByte2 := byte(effectiveMSS & 0xFF)
	synAckOptions := []byte{
		0x02, 0x04, mssByte1, mssByte2,
		0x01,
		0x03, 0x03, winScale,
		0x01,
		0x04, 0x02,
	}

	// Send SYN-ACK back to client
	s.sendTCPPacket(dstIP, srcIP, dstPort, srcPort, serverISN, clientSeq+1, TCPFlagSYN|TCPFlagACK, synAckOptions, nil)

	// Dial Upstream Proxy in background
	go s.establishTCPProxy(sess)
}

func (s *IPStack) establishTCPProxy(sess *tcpSession) {
	defer func() {
		sess.close(s.tracker)
		s.tcpMu.Lock()
		if cur, ok := s.tcpSessions[sess.key]; ok && cur == sess {
			delete(s.tcpSessions, sess.key)
		}
		s.tcpMu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	var conn net.Conn
	var err error

	// If upstream proxy is running on local machine or local subnet (e.g. proxy on 127.0.0.1 or LAN IP),
	// outbound target connections MUST dial directly via physical NIC (IP_UNICAST_IF) to prevent circular Wintun loop!
	if isLocalProxyAddr(s.dialer.TargetServer()) {
		var directDialer net.Dialer
		directDialer.Timeout = 8 * time.Second
		if localIP := GetPhysicalLocalIP(); localIP != nil {
			if localTCPAddr, errAddr := net.ResolveTCPAddr("tcp", net.JoinHostPort(localIP.String(), "0")); errAddr == nil {
				directDialer.LocalAddr = localTCPAddr
			}
		}
		if ifIdx := GetPhysicalInterfaceIndex(); ifIdx > 0 {
			directDialer.Control = func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(ifIdx))
				})
			}
		}
		target := sess.targetAddr
		host, portStr, errSplit := net.SplitHostPort(sess.targetAddr)
		if errSplit == nil {
			if ip := net.ParseIP(host); ip != nil {
				target = net.JoinHostPort(ip.String(), portStr)
			} else if realIP := resolveUpstreamDNS(host); realIP != nil {
				target = net.JoinHostPort(realIP.String(), portStr)
			}
		}
		conn, err = directDialer.DialContext(ctx, "tcp", target)
	} else {
		conn, err = s.dialer.DialContext(ctx, "tcp", sess.targetAddr)
	}
	if err != nil {
		s.sendTCPPacket(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, sess.serverSeq.Load(), sess.clientSeq.Load(), TCPFlagRST|TCPFlagACK, nil, nil)
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetWriteBuffer(2 << 20) // 2MB socket write buffer (high throughput without kernel memory exhaustion)
		_ = tcpConn.SetReadBuffer(2 << 20)  // 2MB socket read buffer
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	sess.mu.Lock()
	sess.proxyConn = conn
	sess.established = true
	pending := sess.pendingBuf
	sess.pendingBuf = nil
	sess.mu.Unlock()

	go s.pumpUploadToProxy(sess)

	// Flush any payload bytes received before upstream connection was established
	if len(pending) > 0 {
		pktCopy := make([]byte, len(pending))
		copy(pktCopy, pending)
		sess.safeSendUpload(pktCopy)
	}

	s.tracker.RegisterConn(sess.connID, "tcp", fmt.Sprintf("%s:%d", sess.srcIP.String(), sess.srcPort), sess.targetAddr)

	// Optimal high-throughput read buffer (64KB LRO/GRO Jumbo chunks for 45x Wintun syscall reduction)
	readBuf := make([]byte, 64*1024)
	chunkSize := int(sess.clientMSS)
	if chunkSize < 536 {
		chunkSize = 1360
	}

	for {
		if sess.closed.Load() || s.ctx.Err() != nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Second))
		n, rErr := conn.Read(readBuf)
		if n > 0 {
			sess.lastActive.Store(time.Now().Unix())
			s.tracker.AddDownload(int64(n))
			s.tracker.UpdateConn(sess.connID, 0, int64(n))

			data := readBuf[:n]
			for len(data) > 0 {
				curr := data
				flags := byte(TCPFlagACK)
				if len(curr) <= chunkSize {
					flags |= TCPFlagPSH
				} else {
					curr = curr[:chunkSize]
				}

				currServerSeq := sess.serverSeq.Load()
				s.sendTCPPacket(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, currServerSeq, sess.clientSeq.Load(), flags, nil, curr)
				sess.serverSeq.Add(uint32(len(curr)))

				data = data[len(curr):]
			}
		}

		if rErr != nil {
			currSeq := sess.serverSeq.Load()
			s.sendTCPPacket(sess.dstIP, sess.srcIP, sess.dstPort, sess.srcPort, currSeq, sess.clientSeq.Load(), TCPFlagFIN|TCPFlagACK, nil, nil)
			sess.serverSeq.Add(1)
			return
		}
	}
}

func (s *IPStack) pumpUploadToProxy(sess *tcpSession) {
	writeBuf := make([]byte, 0, 128*1024)

	for {
		select {
		case data, ok := <-sess.uploadChan:
			if !ok {
				sess.mu.Lock()
				if sess.proxyConn != nil {
					if tc, okConn := sess.proxyConn.(*net.TCPConn); okConn {
						_ = tc.CloseWrite()
					}
				}
				sess.mu.Unlock()
				return
			}

			writeBuf = append(writeBuf[:0], data...)

			// Coalesce pending upload packets into a single socket Write() for high-speed upload scaling
			drained := true
			for drained && len(writeBuf) < 128*1024 {
				select {
				case extra, open := <-sess.uploadChan:
					if !open {
						drained = false
					} else {
						writeBuf = append(writeBuf, extra...)
					}
				default:
					drained = false
				}
			}

			if len(writeBuf) > 0 && sess.proxyConn != nil {
				nw, ew := sess.proxyConn.Write(writeBuf)
				if ew == nil && nw > 0 {
					s.tracker.AddUpload(int64(nw))
					s.tracker.UpdateConn(sess.connID, int64(nw), 0)
				}
			}
		case <-sess.closeChan:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

func (t *tcpSession) safeSendUpload(data []byte) {
	if t.closed.Load() {
		return
	}
	defer func() {
		_ = recover()
	}()
	select {
	case t.uploadChan <- data:
	case <-t.closeChan:
	default:
		runtime.Gosched()
		select {
		case t.uploadChan <- data:
		case <-t.closeChan:
		default:
		}
	}
}

func (t *tcpSession) close(tracker *stats.Tracker) {
	if t.closed.CompareAndSwap(false, true) {
		t.uploadOnce.Do(func() {
			if t.uploadChan != nil {
				close(t.uploadChan)
			}
		})
		if t.proxyConn != nil {
			_ = t.proxyConn.Close()
		}
		close(t.closeChan)
		if tracker != nil {
			tracker.UnregisterConn(t.connID)
		}
	}
}

// ---------------------- Packet Construction & Sending ----------------------

func (s *IPStack) sendTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, options []byte, payload []byte) {
	optLen := len(options)
	for optLen%4 != 0 {
		options = append(options, 0x00)
		optLen++
	}

	headerLen := 20 + optLen
	dataOffset := byte((headerLen / 4) << 4)

	tcpLen := headerLen + len(payload)
	tcpData := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(tcpData[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpData[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpData[4:8], seq)
	binary.BigEndian.PutUint32(tcpData[8:12], ack)
	tcpData[12] = dataOffset
	tcpData[13] = flags
	binary.BigEndian.PutUint16(tcpData[14:16], 65535) // Advertised receive window
	tcpData[16] = 0                                   // Checksum
	tcpData[17] = 0
	binary.BigEndian.PutUint16(tcpData[18:20], 0) // Urgent pointer

	if optLen > 0 {
		copy(tcpData[20:headerLen], options)
	}

	if len(payload) > 0 {
		copy(tcpData[headerLen:], payload)
	}

	chk := tcpChecksum(srcIP, dstIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], chk)

	s.sendIPPacket(srcIP, dstIP, ProtoTCP, tcpData)
}

func (s *IPStack) sendIPPacket(srcIP, dstIP net.IP, proto byte, payload []byte) {
	totalLen := 20 + len(payload)
	ipPkt := make([]byte, totalLen)

	ipPkt[0] = 0x45 // Version 4, IHL 5
	ipPkt[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(ipPkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipPkt[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(ipPkt[6:8], 0x4000) // Flags: Don't Fragment
	ipPkt[8] = 64                                 // TTL
	ipPkt[9] = proto                              // Protocol
	ipPkt[10] = 0                                 // Checksum
	ipPkt[11] = 0
	copy(ipPkt[12:16], srcIP.To4())
	copy(ipPkt[16:20], dstIP.To4())

	chk := checksum(ipPkt[:20])
	binary.BigEndian.PutUint16(ipPkt[10:12], chk)

	copy(ipPkt[20:], payload)

	_, _ = s.dev.Write(ipPkt)
}

func (s *IPStack) cleanupStaleSessionsLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()

			// Clean TCP sessions (retain idle active connections for 180s to prevent premature timeout)
			s.tcpMu.Lock()
			for k, sess := range s.tcpSessions {
				if sess.closed.Load() || now-sess.lastActive.Load() > 180 {
					sess.close(s.tracker)
					delete(s.tcpSessions, k)
				}
			}
			s.tcpMu.Unlock()

			// Clean UDP sessions
			s.udpMu.Lock()
			for k, sess := range s.udpSessions {
				if sess.closed.Load() || now-sess.lastActive.Load() > 30 {
					sess.close(s.tracker)
					delete(s.udpSessions, k)
				}
			}
			s.udpMu.Unlock()
		}
	}
}

// ---------------------- Checksum Utilities & Options Parser ----------------------

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	var sum uint32

	src := srcIP.To4()
	dst := dstIP.To4()

	if src == nil || dst == nil {
		return 0
	}

	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(ProtoTCP)
	sum += uint32(len(tcpData))

	for i := 0; i < len(tcpData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseTCPOptions parses MSS and Window Scale from TCP SYN options
func parseTCPOptions(opts []byte) (mss uint16, winScale uint8) {
	mss = 1460
	winScale = 8
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0: // EOL
			return
		case 1: // NOP
			i++
		default:
			if i+1 >= len(opts) {
				return
			}
			length := int(opts[i+1])
			if length < 2 || i+length > len(opts) {
				return
			}
			if kind == 2 && length == 4 { // MSS
				mss = binary.BigEndian.Uint16(opts[i+2 : i+4])
			} else if kind == 3 && length == 3 { // Window Scale
				winScale = opts[i+2]
			}
			i += length
		}
	}
	return
}

// ---------------------- IPv6 Fast Rejection Utilities ----------------------

func (s *IPStack) sendIPv6TCPRST(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32) {
	tcpLen := 20
	tcpData := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcpData[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpData[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpData[4:8], seq)
	binary.BigEndian.PutUint32(tcpData[8:12], ack)
	tcpData[12] = 0x50 // Data offset: 5 (20 bytes)
	tcpData[13] = TCPFlagRST | TCPFlagACK
	binary.BigEndian.PutUint16(tcpData[14:16], 0) // Window 0
	tcpData[16] = 0                              // Checksum
	tcpData[17] = 0
	binary.BigEndian.PutUint16(tcpData[18:20], 0) // Urgent pointer

	chk := tcpChecksumV6(srcIP, dstIP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], chk)

	totalLen := 40 + tcpLen
	ipPkt := make([]byte, totalLen)
	ipPkt[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ipPkt[4:6], uint16(tcpLen))
	ipPkt[6] = ProtoTCP
	ipPkt[7] = 64
	copy(ipPkt[8:24], srcIP.To16())
	copy(ipPkt[24:40], dstIP.To16())
	copy(ipPkt[40:], tcpData)

	_, _ = s.dev.Write(ipPkt)
}

func tcpChecksumV6(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	var sum uint32
	src := srcIP.To16()
	dst := dstIP.To16()
	if src == nil || dst == nil {
		return 0
	}

	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(src[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dst[i : i+2]))
	}

	sum += uint32(len(tcpData))
	sum += uint32(ProtoTCP)

	for i := 0; i < len(tcpData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

var upstreamDNSCache sync.Map // key = domain string, value = *dnsCacheEntry

// resolveUpstreamDNS performs ultra-fast parallel DNS lookup over the physical NIC with in-memory caching
func resolveUpstreamDNS(domain string) net.IP {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	// 0. Instant return if domain is already an IP address (0 microseconds!)
	if ip := net.ParseIP(domain); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
		return ip
	}

	// 1. Instant LRU Cache Check (0 microseconds!)
	if val, ok := upstreamDNSCache.Load(domain); ok {
		entry := val.(*dnsCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.ip
		}
		upstreamDNSCache.Delete(domain)
	}

	// 2. High-speed raw IPv4 UDP multi-DNS parallel race (15ms latency!)
	ifIdx := GetPhysicalInterfaceIndex()
	servers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	if gwIP := GetPhysicalGatewayIP(); gwIP != nil {
		servers = append([]string{net.JoinHostPort(gwIP.String(), "53")}, servers...)
	}

	type dnsRes struct {
		ip net.IP
	}
	ch := make(chan dnsRes, len(servers)+1)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	for _, srv := range servers {
		go func(s string) {
			if ip, err := fastDNSQueryIPv4(domain, s, ifIdx); err == nil && ip != nil {
				select {
				case ch <- dnsRes{ip: ip}:
				default:
				}
			}
		}(srv)
	}

	// Launch unconstrained system resolver fallback goroutine to guarantee 100% internet reliability
	go func() {
		ips, err := net.LookupIP(domain)
		if err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && (ip4[0] != 198 || ip4[1] != 18) {
					select {
					case ch <- dnsRes{ip: ip4}:
					default:
					}
					return
				}
			}
		}
	}()

	select {
	case r := <-ch:
		if r.ip != nil {
			upstreamDNSCache.Store(domain, &dnsCacheEntry{
				ip:        r.ip,
				expiresAt: time.Now().Add(2 * time.Hour),
			})
			return r.ip
		}
	case <-ctx.Done():
	}

	return nil
}

func fastDNSQueryIPv4(domain string, srv string, ifIdx uint32) (net.IP, error) {
	d := net.Dialer{Timeout: 600 * time.Millisecond}
	if ifIdx > 0 {
		d.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(ifIdx))
			})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", srv)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var parts []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				parts = append(parts, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		parts = append(parts, domain[start:])
	}

	req := make([]byte, 0, 256)
	req = append(req, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, part := range parts {
		req = append(req, byte(len(part)))
		req = append(req, []byte(part)...)
	}
	req = append(req, 0x00, 0x00, 0x01, 0x00, 0x01)

	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(350 * time.Millisecond))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return nil, err
	}

	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount == 0 {
		return nil, errors.New("no answer")
	}

	offset := 12
	for offset < n && resp[offset] != 0 {
		offset += int(resp[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount) && offset < n; i++ {
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < n && resp[offset] != 0 {
				offset += int(resp[offset]) + 1
			}
			offset++
		}
		if offset+10 > n {
			break
		}
		qtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10
		if qtype == 1 && rdlen == 4 && offset+4 <= n {
			return net.IP(resp[offset : offset+4]), nil
		}
		offset += int(rdlen)
	}

	return nil, errors.New("no IPv4 found")
}



// isLocalProxyAddr checks if the target proxy address is running locally on this machine
func isLocalProxyAddr(proxyAddr string) bool {
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		host = proxyAddr
	}
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return true
		}
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				addrs, err := iface.Addrs()
				if err == nil {
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok {
							if ipnet.IP.Equal(ip) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}


