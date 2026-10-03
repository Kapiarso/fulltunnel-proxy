package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseProxyString parses quick proxy strings like:
// - "198.51.100.1:1080"
// - "198.51.100.1:1080:user:pass"
// - "user:pass@198.51.100.1:1080"
// - "socks5://user:pass@198.51.100.1:1080"
func ParseProxyString(raw string, defaultType ProxyType) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("proxy string cannot be empty")
	}

	if defaultType == "" {
		defaultType = ProxyTypeSOCKS5
	}

	profile := &Profile{
		ID:        fmt.Sprintf("prof-%d", len(raw)),
		Name:      "Quick Proxy",
		Type:      defaultType,
		EnableUDP: true,
		DNSMode:   DNSModeFakeIP,
		BypassLAN: true,
	}

	// 1. Check URI format: socks5://... or http://...
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil && u.Host != "" {
			switch strings.ToLower(u.Scheme) {
			case "socks5", "socks", "socks5h":
				profile.Type = ProxyTypeSOCKS5
			case "http":
				profile.Type = ProxyTypeHTTP
			case "https":
				profile.Type = ProxyTypeHTTPS
			}

			host, portStr, err := net.SplitHostPort(u.Host)
			if err == nil {
				profile.Host = host
				port, _ := strconv.Atoi(portStr)
				profile.Port = port
			} else {
				profile.Host = u.Host
				if profile.Type == ProxyTypeSOCKS5 {
					profile.Port = 1080
				} else {
					profile.Port = 8080
				}
			}

			if u.User != nil {
				profile.Username = u.User.Username()
				profile.Password, _ = u.User.Password()
			}
			return profile, nil
		}
	}

	// 2. Check user:pass@host:port format
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		userPass := parts[0]
		hostPort := parts[1]

		if strings.Contains(userPass, ":") {
			up := strings.SplitN(userPass, ":", 2)
			profile.Username = up[0]
			profile.Password = up[1]
		} else {
			profile.Username = userPass
		}

		host, portStr, err := net.SplitHostPort(hostPort)
		if err == nil {
			profile.Host = host
			profile.Port, _ = strconv.Atoi(portStr)
		} else {
			profile.Host = hostPort
			profile.Port = 1080
		}
		return profile, nil
	}

	// 3. Colon-separated format: host:port OR host:port:user:pass
	parts := strings.Split(raw, ":")
	if len(parts) >= 4 {
		// host:port:user:pass
		profile.Host = parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %s", parts[1])
		}
		profile.Port = port
		profile.Username = parts[2]
		profile.Password = strings.Join(parts[3:], ":") // Allow colon in password
		return profile, nil
	} else if len(parts) == 2 {
		// host:port
		profile.Host = parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %s", parts[1])
		}
		profile.Port = port
		profile.Username = ""
		profile.Password = ""
		return profile, nil
	} else if len(parts) == 3 {
		// host:port:user (without password)
		profile.Host = parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port %s", parts[1])
		}
		profile.Port = port
		profile.Username = parts[2]
		profile.Password = ""
		return profile, nil
	}

	return nil, fmt.Errorf("unrecognized proxy format, expected 'host:port' or 'host:port:user:pass'")
}
