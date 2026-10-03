package core

import (
	"os/exec"

	"golang.org/x/sys/windows"
)

// IsAdmin checks if the current process has Administrator privileges
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil || !member {
		return false
	}

	return token.IsElevated()
}

// EnsureAdmin checks if elevated privileges are present without triggering auto-relaunch loops
func EnsureAdmin() bool {
	if IsAdmin() {
		EnsureFirewallAndP2POptimization()
	}
	return IsAdmin()
}

// EnsureFirewallAndP2POptimization automatically configures Windows Firewall rules for Radmin P2P UDP ports & SecureTunnel
func EnsureFirewallAndP2POptimization() {
	if !IsAdmin() {
		return
	}
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=SecureTunnel Radmin P2P UDP", "dir=in", "action=allow", "protocol=UDP", "localport=48650,17777,3478").Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=SecureTunnel Radmin P2P UDP Out", "dir=out", "action=allow", "protocol=UDP", "localport=48650,17777,3478").Run()
}

