package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

// FakeIPPool manages the mapping between domain names and synthetic IP addresses in 198.18.0.0/15
type FakeIPPool struct {
	mu           sync.RWMutex
	baseIP       uint32
	maxOffset    uint32
	current      uint32
	domainToIP   map[string]net.IP
	ipToDomain   map[string]string
	cidrNet      *net.IPNet
}

// NewFakeIPPool initializes a Fake-IP allocator for 198.18.0.0/15 (RFC 2544 benchmark pool)
func NewFakeIPPool(cidrStr string) (*FakeIPPool, error) {
	if cidrStr == "" {
		cidrStr = "198.18.0.0/15"
	}

	ip, ipnet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipnet.Mask.Size()
	totalHostCount := uint32(1 << (bits - ones))

	base := binary.BigEndian.Uint32(ip.To4())
	// Skip network address .0 and start at .2
	base += 2

	return &FakeIPPool{
		baseIP:     base,
		maxOffset:  totalHostCount - 4,
		current:    0,
		domainToIP: make(map[string]net.IP),
		ipToDomain: make(map[string]string),
		cidrNet:    ipnet,
	}, nil
}

// Contains checks if an IP belongs to the Fake-IP pool
func (f *FakeIPPool) Contains(ip net.IP) bool {
	return f.cidrNet.Contains(ip)
}

// Allocate assigns a Fake-IP to a domain name, or returns the existing allocation
func (f *FakeIPPool) Allocate(domain string) net.IP {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	f.mu.Lock()
	defer f.mu.Unlock()

	if ip, exists := f.domainToIP[domain]; exists {
		return ip
	}

	// Allocate next sequential IP in pool
	newVal := f.baseIP + (f.current % f.maxOffset)
	f.current++

	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, newVal)
	allocatedIP := net.IP(ipBytes)

	// Clean up old reverse mapping if this IP was previously mapped
	oldDomain, hadOld := f.ipToDomain[allocatedIP.String()]
	if hadOld {
		delete(f.domainToIP, oldDomain)
	}

	f.domainToIP[domain] = allocatedIP
	f.ipToDomain[allocatedIP.String()] = domain

	return allocatedIP
}

// LookupDomain resolves a Fake-IP back to the original domain name
func (f *FakeIPPool) LookupDomain(ip net.IP) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	domain, found := f.ipToDomain[ip.String()]
	return domain, found
}

// LookupIP retrieves the mapped Fake-IP for a domain if present
func (f *FakeIPPool) LookupIP(domain string) (net.IP, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	f.mu.RLock()
	defer f.mu.RUnlock()

	ip, found := f.domainToIP[domain]
	return ip, found
}
