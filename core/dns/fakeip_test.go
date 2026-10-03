package dns

import (
	"net"
	"testing"
)

func TestFakeIPAllocation(t *testing.T) {
	pool, err := NewFakeIPPool("198.18.0.0/15")
	if err != nil {
		t.Fatalf("failed to create fake ip pool: %v", err)
	}

	domain := "example.com"
	ip1 := pool.Allocate(domain)
	if ip1 == nil {
		t.Fatal("allocated IP is nil")
	}

	if !pool.Contains(ip1) {
		t.Fatalf("allocated IP %s is not in Fake-IP pool", ip1.String())
	}

	// Idempotency: same domain returns same IP
	ip2 := pool.Allocate(domain)
	if ip1.String() != ip2.String() {
		t.Fatalf("expected same IP %s, got %s", ip1.String(), ip2.String())
	}

	// Reverse lookup
	resolvedDomain, found := pool.LookupDomain(ip1)
	if !found || resolvedDomain != domain {
		t.Fatalf("expected domain %s, got %s (found: %v)", domain, resolvedDomain, found)
	}

	// Different domain gets different IP
	otherIP := pool.Allocate("google.com")
	if otherIP.String() == ip1.String() {
		t.Fatalf("different domains should receive different Fake-IPs")
	}
}

func TestFakeIPPoolContains(t *testing.T) {
	pool, _ := NewFakeIPPool("198.18.0.0/15")

	if !pool.Contains(net.ParseIP("198.18.1.1")) {
		t.Error("expected 198.18.1.1 to be in pool")
	}
	if pool.Contains(net.ParseIP("1.1.1.1")) {
		t.Error("expected 1.1.1.1 to NOT be in pool")
	}
}
