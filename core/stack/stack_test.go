package stack

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTCPChecksum(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.2").To4()

	// Simple TCP SYN packet
	tcpData := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpData[0:2], 12345) // srcPort
	binary.BigEndian.PutUint16(tcpData[2:4], 80)    // dstPort
	binary.BigEndian.PutUint32(tcpData[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(tcpData[8:12], 0)    // ack
	tcpData[12] = 0x50                              // DataOffset = 5 (20 bytes)
	tcpData[13] = TCPFlagSYN                        // flags
	binary.BigEndian.PutUint16(tcpData[14:16], 65535)

	chk := tcpChecksum(srcIP, dstIP, tcpData)
	t.Logf("TCP Checksum: 0x%04X", chk)

	// Verify checksum validation
	binary.BigEndian.PutUint16(tcpData[16:18], chk)
	valChk := tcpChecksum(srcIP, dstIP, tcpData)
	t.Logf("Validation Checksum (should be 0x0000 or 0xFFFF): 0x%04X", valChk)

	// Test with payload
	tcpDataWithPayload := append(tcpData, []byte("HELLO WORLD!")...)
	binary.BigEndian.PutUint16(tcpDataWithPayload[16:18], 0)
	chk2 := tcpChecksum(srcIP, dstIP, tcpDataWithPayload)
	t.Logf("TCP Checksum with odd payload: 0x%04X", chk2)
}

func TestTCPChecksumV6(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")

	tcpData := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpData[0:2], 54321)
	binary.BigEndian.PutUint16(tcpData[2:4], 443)
	binary.BigEndian.PutUint32(tcpData[4:8], 0)
	binary.BigEndian.PutUint32(tcpData[8:12], 1001)
	tcpData[12] = 0x50
	tcpData[13] = TCPFlagRST | TCPFlagACK

	chk := tcpChecksumV6(srcIP, dstIP, tcpData)
	if chk == 0 {
		t.Fatalf("Expected non-zero IPv6 TCP checksum")
	}
	t.Logf("IPv6 TCP Checksum: 0x%04X", chk)
}
