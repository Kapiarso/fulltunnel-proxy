package proxy

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapUDPPacket(t *testing.T) {
	targetHost := "192.168.1.100"
	targetPort := 8080
	payload := []byte("Hello Enterprise Tunnel UDP!")

	wrapped, err := WrapUDPPacket(targetHost, targetPort, payload)
	if err != nil {
		t.Fatalf("WrapUDPPacket failed: %v", err)
	}

	unwrappedPayload, srcAddr, err := UnwrapUDPPacket(wrapped)
	if err != nil {
		t.Fatalf("UnwrapUDPPacket failed: %v", err)
	}

	if !bytes.Equal(payload, unwrappedPayload) {
		t.Fatalf("payload mismatch: expected %s, got %s", string(payload), string(unwrappedPayload))
	}

	if srcAddr != "192.168.1.100:8080" {
		t.Fatalf("expected address 192.168.1.100:8080, got %s", srcAddr)
	}
}

func TestWrapUnwrapDomainUDPPacket(t *testing.T) {
	domainHost := "dns.google.com"
	targetPort := 53
	payload := []byte{0x12, 0x34, 0x01, 0x00}

	wrapped, err := WrapUDPPacket(domainHost, targetPort, payload)
	if err != nil {
		t.Fatalf("WrapUDPPacket failed: %v", err)
	}

	unwrappedPayload, srcAddr, err := UnwrapUDPPacket(wrapped)
	if err != nil {
		t.Fatalf("UnwrapUDPPacket failed: %v", err)
	}

	if !bytes.Equal(payload, unwrappedPayload) {
		t.Fatalf("payload mismatch")
	}

	if srcAddr != "dns.google.com:53" {
		t.Fatalf("expected address dns.google.com:53, got %s", srcAddr)
	}
}
