package config

import "testing"

func TestParseProxyString(t *testing.T) {
	// 1. host:port:user:pass
	p1, err := ParseProxyString("198.51.100.1:1080:admin:secret123", ProxyTypeSOCKS5)
	if err != nil {
		t.Fatalf("p1 failed: %v", err)
	}
	if p1.Host != "198.51.100.1" || p1.Port != 1080 || p1.Username != "admin" || p1.Password != "secret123" {
		t.Fatalf("p1 values mismatch: %+v", p1)
	}

	// 2. host:port (No auth)
	p2, err := ParseProxyString("198.51.100.1:1080", ProxyTypeSOCKS5)
	if err != nil {
		t.Fatalf("p2 failed: %v", err)
	}
	if p2.Host != "198.51.100.1" || p2.Port != 1080 || p2.Username != "" || p2.Password != "" {
		t.Fatalf("p2 values mismatch: %+v", p2)
	}

	// 3. socks5 URI
	p3, err := ParseProxyString("socks5://myuser:mypass@proxy.corp.com:10808", ProxyTypeHTTP)
	if err != nil {
		t.Fatalf("p3 failed: %v", err)
	}
	if p3.Type != ProxyTypeSOCKS5 || p3.Host != "proxy.corp.com" || p3.Port != 10808 || p3.Username != "myuser" || p3.Password != "mypass" {
		t.Fatalf("p3 values mismatch: %+v", p3)
	}
}
