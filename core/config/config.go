package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ProxyType defines the supported upstream proxy protocols
type ProxyType string

const (
	ProxyTypeSOCKS5 ProxyType = "socks5"
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeHTTPS  ProxyType = "https"
)

// DNSMode defines the DNS interception strategy
type DNSMode string

const (
	DNSModeFakeIP   DNSMode = "fakeip"
	DNSModeRemote   DNSMode = "remote"
	DNSModeDirect   DNSMode = "direct"
)

// Profile represents a saved proxy configuration
type Profile struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      ProxyType `json:"type"`      // "socks5", "http", "https"
	Host      string    `json:"host"`      // e.g. "proxy.company.com" or "1.2.3.4"
	Port      int       `json:"port"`      // e.g. 1080, 8080
	Username  string    `json:"username"`  // RFC 1929 username
	Password  string    `json:"password"`  // RFC 1929 password
	EnableUDP bool      `json:"enable_udp"`// UDP Associate for games/VoIP
	DNSMode   DNSMode   `json:"dns_mode"`  // "fakeip" recommended
	BypassLAN bool      `json:"bypass_lan"`// Bypass 10.0.0.0/8, 192.168.0.0/16, etc.
}

// Config represents the overall application configuration
type Config struct {
	ActiveProfileID string    `json:"active_profile_id"`
	Profiles        []Profile `json:"profiles"`
	TunName         string    `json:"tun_name"`        // e.g. "SecureTunnel"
	TunIP           string    `json:"tun_ip"`          // default "172.19.0.1"
	TunMask         string    `json:"tun_mask"`        // default "255.255.255.252"
	TunGateway      string    `json:"tun_gateway"`     // default "172.19.0.2"
	DNSAddress      string    `json:"dns_address"`     // default "172.19.0.2:53"
	FakeIPPool      string    `json:"fake_ip_pool"`    // default "198.18.0.0/15"
	MTU             int       `json:"mtu"`             // default 1500
	HTTPPort        int       `json:"http_port"`       // default 28888 for UI/API
	AutoStart       bool      `json:"auto_start"`
	KillSwitch      bool      `json:"kill_switch"`
}

// DefaultConfig returns reasonable enterprise defaults
func DefaultConfig() *Config {
	defaultProfile := Profile{
		ID:        "default-1",
		Name:      "Default SOCKS5 Proxy",
		Type:      ProxyTypeSOCKS5,
		Host:      "127.0.0.1",
		Port:      1080,
		Username:  "",
		Password:  "",
		EnableUDP: true,
		DNSMode:   DNSModeDirect,
		BypassLAN: true,
	}

	return &Config{
		ActiveProfileID: "default-1",
		Profiles:        []Profile{defaultProfile},
		TunName:         "SecureTunnel",
		TunIP:           "172.19.0.1",
		TunMask:         "255.255.255.252",
		TunGateway:      "172.19.0.2",
		DNSAddress:      "172.19.0.2:53",
		FakeIPPool:      "198.18.0.0/15",
		MTU:             1400,
		HTTPPort:        28888,
		AutoStart:       false,
		KillSwitch:      true,
	}
}

// GetActiveProfile retrieves the currently selected profile
func (c *Config) GetActiveProfile() *Profile {
	for i := range c.Profiles {
		if c.Profiles[i].ID == c.ActiveProfileID {
			return &c.Profiles[i]
		}
	}
	if len(c.Profiles) > 0 {
		return &c.Profiles[0]
	}
	return nil
}

// ConfigFilePath returns the path to the config JSON file
func ConfigFilePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "securetunnel_config.json"
	}
	targetDir := filepath.Join(configDir, "SecureTunnel")
	_ = os.MkdirAll(targetDir, 0755)
	return filepath.Join(targetDir, "config.json")
}

// LoadConfig loads the config from disk or returns default
func LoadConfig() (*Config, error) {
	path := ConfigFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		cfg := DefaultConfig()
		_ = cfg.Save()
		return cfg, nil
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultConfig(), err
	}
	return &cfg, nil
}

// Save writes config to disk
func (c *Config) Save() error {
	path := ConfigFilePath()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
