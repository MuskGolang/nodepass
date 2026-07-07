// config.go parses tunnel configuration from URL query parameters and populates
// the Common struct fields: pool capacity, run mode, TLS code, rate limits,
// slot limits, DNS TTL, load-balancing strategy, and protocol block lists.
package common

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"time"
)

// GetAddress parses the tunnel and target addresses from the parsed URL, resolves them to both TCP and UDP
// net.Addr values, validates them, and stores the results in the corresponding Common fields.
// Returns an error if any address is missing, unresolvable, or if the tunnel port conflicts with a target
// address on the loopback interface (indicating misconfiguration). Must be called first during InitConfig.
func (c *Common) GetAddress() error {
	tunnelAddr := c.ParsedURL.Host
	if tunnelAddr == "" {
		return fmt.Errorf("GetAddress: no valid tunnel address found")
	}

	c.TunnelAddr = tunnelAddr
	if name, port, err := net.SplitHostPort(tunnelAddr); err == nil {
		c.ServerName, c.ServerPort = name, port
	}

	tcpAddr, err := c.ResolveAddr("tcp", tunnelAddr)
	if err != nil {
		return fmt.Errorf("GetAddress: resolveTCPAddr failed: %w", err)
	}
	c.TunnelTCPAddr = tcpAddr.(*net.TCPAddr)

	udpAddr, err := c.ResolveAddr("udp", tunnelAddr)
	if err != nil {
		return fmt.Errorf("GetAddress: resolveUDPAddr failed: %w", err)
	}
	c.TunnelUDPAddr = udpAddr.(*net.UDPAddr)

	targetAddr := strings.TrimPrefix(c.ParsedURL.Path, "/")
	if targetAddr == "" {
		return fmt.Errorf("GetAddress: no valid target address found")
	}

	addrList := strings.Split(targetAddr, ",")
	tempTCPAddrs := make([]*net.TCPAddr, 0, len(addrList))
	tempUDPAddrs := make([]*net.UDPAddr, 0, len(addrList))
	tempRawAddrs := make([]string, 0, len(addrList))

	for _, addr := range addrList {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}

		tcpAddr, err := c.ResolveAddr("tcp", addr)
		if err != nil {
			return fmt.Errorf("GetAddress: resolveTCPAddr failed for %s: %w", addr, err)
		}

		udpAddr, err := c.ResolveAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("GetAddress: resolveUDPAddr failed for %s: %w", addr, err)
		}

		tempTCPAddrs = append(tempTCPAddrs, tcpAddr.(*net.TCPAddr))
		tempUDPAddrs = append(tempUDPAddrs, udpAddr.(*net.UDPAddr))
		tempRawAddrs = append(tempRawAddrs, addr)
	}

	if len(tempTCPAddrs) == 0 || len(tempUDPAddrs) == 0 || len(tempTCPAddrs) != len(tempUDPAddrs) {
		return fmt.Errorf("GetAddress: no valid target address found")
	}

	c.TargetAddrs = tempRawAddrs
	c.TargetTCPAddrs = tempTCPAddrs
	c.TargetUDPAddrs = tempUDPAddrs
	c.TargetIdx = 0

	tunnelPort := c.TunnelTCPAddr.Port
	for _, targetAddr := range c.TargetTCPAddrs {
		if targetAddr.Port == tunnelPort && (targetAddr.IP.IsLoopback() || c.TunnelTCPAddr.IP.IsUnspecified()) {
			return fmt.Errorf("GetAddress: tunnel port %d conflicts with target address %s", tunnelPort, targetAddr.String())
		}
	}

	return nil
}

// GetCoreType reads the URL scheme and stores it in CoreType. Valid values are "client" or "server".
// Used to determine the role of this tunnel endpoint (initiator or responder).
func (c *Common) GetCoreType() {
	c.CoreType = c.ParsedURL.Scheme
}

// GetTunnelKey derives the pre-shared tunnel key from the URL for XOR obfuscation of control signals.
// If a username is present in the URL, it is used directly. Otherwise, a stable 4-byte FNV-1a hash
// of the port string is computed and hex-encoded. This key must match between client and server.
func (c *Common) GetTunnelKey() {
	if key := c.ParsedURL.User.Username(); key != "" {
		c.TunnelKey = key
	} else {
		hash := fnv.New32a()
		hash.Write([]byte(c.ParsedURL.Port()))
		c.TunnelKey = hex.EncodeToString(hash.Sum(nil))
	}
}

// GetDNSTTL reads the "dns" query parameter (e.g. dns=10m) and sets the DNS cache TTL.
// Falls back to DefaultDNSTTL when the parameter is absent, unparseable, or has a negative value.
// Determines how long cached DNS entries remain valid before re-resolution.
func (c *Common) GetDNSTTL() {
	if dns := c.ParsedURL.Query().Get("dns"); dns != "" {
		if ttl, err := time.ParseDuration(dns); err == nil && ttl > 0 {
			c.DNSCacheTTL = ttl
		}
	} else {
		c.DNSCacheTTL = DefaultDNSTTL
	}
}

// GetServerName sets the TLS Server Name Indication (SNI) hostname for the tunnel endpoint.
// The "sni" query parameter takes precedence. If absent, the tunnel hostname is used when it is a DNS name.
// IP addresses and empty hostnames fall back to DefaultServerName ("none") to indicate IP-based or no-SNI connection.
func (c *Common) GetServerName() {
	if serverName := c.ParsedURL.Query().Get("sni"); serverName != "" {
		c.ServerName = serverName
		return
	}
	if c.ServerName == "" || net.ParseIP(c.ServerName) != nil {
		c.ServerName = DefaultServerName
	}
}

// GetLBStrategy reads the "lbs" query parameter and sets the load-balancing strategy:
// "0"=round-robin (default, stateless sequential cycling), "1"=lowest-latency (uses ProbeBestTarget result),
// "2"=primary-failover (sticks to primary until FallbackInterval elapses).
func (c *Common) GetLBStrategy() {
	if lbStrategy := c.ParsedURL.Query().Get("lbs"); lbStrategy != "" {
		c.LBStrategy = lbStrategy
	} else {
		c.LBStrategy = DefaultLBStrategy
	}
}

// GetPoolCapacity reads "min" and "max" query parameters to set the connection pool bounds.
// Both default to DefaultMinPool/DefaultMaxPool when absent, unparseable, or non-positive.
// MinPoolCapacity determines how many connections to maintain; MaxPoolCapacity prevents unbounded growth.
func (c *Common) GetPoolCapacity() {
	if min := c.ParsedURL.Query().Get("min"); min != "" {
		if value, err := strconv.Atoi(min); err == nil && value > 0 {
			c.MinPoolCapacity = value
		}
	} else {
		c.MinPoolCapacity = DefaultMinPool
	}

	if max := c.ParsedURL.Query().Get("max"); max != "" {
		if value, err := strconv.Atoi(max); err == nil && value > 0 {
			c.MaxPoolCapacity = value
		}
	} else {
		c.MaxPoolCapacity = DefaultMaxPool
	}
}

// GetRunMode reads the "mode" query parameter: "0"=auto-detect (single for one target, pool for multiple),
// "1"=single-connection (fresh dial per connection, no pool), "2"=pool mode (always use connection pool).
func (c *Common) GetRunMode() {
	if mode := c.ParsedURL.Query().Get("mode"); mode != "" {
		c.RunMode = mode
	} else {
		c.RunMode = DefaultRunMode
	}
}

// GetPoolType reads the "type" query parameter and selects the tunnel pool backend.
// NodePass keeps this query key for URL compatibility while exposing it as the
// --pool CLI flag. QUIC requires TLS material, so tls=0 is upgraded to code-1.
func (c *Common) GetPoolType() {
	if poolType := c.ParsedURL.Query().Get("type"); poolType != "" {
		c.PoolType = poolType
	} else {
		c.PoolType = DefaultPoolType
	}
	if c.PoolType == "1" && c.TLSCode == "0" {
		c.TLSCode = "1"
	}
}

// GetDialerIP reads the "dial" query parameter to bind outbound connections to a specific local IP address.
// "auto" (default) lets the OS choose using the system default route. An invalid IP address logs a warning
// and falls back to "auto". Used to support multi-homed systems or specific network interface selection.
func (c *Common) GetDialerIP() {
	if dialerIP := c.ParsedURL.Query().Get("dial"); dialerIP != "" && dialerIP != "auto" {
		if ip := net.ParseIP(dialerIP); ip != nil {
			c.DialerIP = dialerIP
			c.DialerIPv6 = ip.To4() == nil
			return
		} else {
			c.Logger.Error("GetDialerIP: fallback to system auto due to invalid IP address: %v", dialerIP)
		}
	}
	c.DialerIP = DefaultDialerIP
}

// GetReadTimeout reads the "read" query parameter and sets a per-connection read deadline (e.g. read=30s).
// 0 (default) disables the deadline, allowing indefinite reads. Used to prevent connections from hanging
// indefinitely when the peer stops sending data. Falls back to DefaultReadTimeout when parameter is absent or invalid.
func (c *Common) GetReadTimeout() {
	if timeout := c.ParsedURL.Query().Get("read"); timeout != "" {
		if value, err := time.ParseDuration(timeout); err == nil && value > 0 {
			c.ReadTimeout = value
		}
	} else {
		c.ReadTimeout = DefaultReadTimeout
	}
}

// GetRateLimit reads the "rate" query parameter in Megabits per second and converts to bytes/s for the token bucket.
// Conversion: Mbit/s * 125000 = bytes/s (1 Mbit = 125000 bytes). 0 (default) disables rate limiting (unlimited).
// Used to prevent the tunnel from saturating the underlying link or exceeding service quotas.
func (c *Common) GetRateLimit() {
	if limit := c.ParsedURL.Query().Get("rate"); limit != "" {
		if value, err := strconv.Atoi(limit); err == nil && value > 0 {
			c.RateLimit = value * 125000 // convert Mbit/s to bytes/s
		}
	} else {
		c.RateLimit = DefaultRateLimit
	}
}

// GetSlotLimit reads the "slot" query parameter and sets the maximum number of simultaneous TCP/UDP connections.
// Prevents unbounded resource allocation when handling many concurrent tunnel clients. Defaults to DefaultSlotLimit (65536).
func (c *Common) GetSlotLimit() {
	if slot := c.ParsedURL.Query().Get("slot"); slot != "" {
		if value, err := strconv.Atoi(slot); err == nil && value > 0 {
			c.SlotLimit = int32(value)
		}
	} else {
		c.SlotLimit = DefaultSlotLimit
	}
}

// GetProxyProtocol reads the "proxy" query parameter. "1" enables emitting PROXY Protocol v1 headers
// on outbound connections to the target. Required when the tunnel is behind upstream proxies that expect HAProxy-compatible headers.
func (c *Common) GetProxyProtocol() {
	if protocol := c.ParsedURL.Query().Get("proxy"); protocol != "" {
		c.ProxyProtocol = protocol
	} else {
		c.ProxyProtocol = DefaultProxyProtocol
	}
}

// GetBlockProtocol reads the "block" query parameter, which is a bitmask string controlling protocol blocking:
// "1" blocks SOCKS4/SOCKS5, "2" blocks HTTP CONNECT, "4" blocks TLS ClientHello.
// Multiple protocols can be combined (e.g. "12" blocks both SOCKS and HTTP). Useful for preventing tunnel abuse.
// Also parses and sets boolean flags (BlockSOCKS, BlockHTTP, BlockTLS) for fast runtime checking.
func (c *Common) GetBlockProtocol() {
	if protocol := c.ParsedURL.Query().Get("block"); protocol != "" {
		c.BlockProtocol = protocol
	} else {
		c.BlockProtocol = DefaultBlockProtocol
	}
	c.BlockSOCKS = strings.Contains(c.BlockProtocol, "1")
	c.BlockHTTP = strings.Contains(c.BlockProtocol, "2")
	c.BlockTLS = strings.Contains(c.BlockProtocol, "3")
}

// GetTCPStrategy reads the "notcp" query parameter. "1" suppresses the TCP data path entirely,
// leaving only UDP active. Used to disable TCP tunneling when only UDP is desired.
func (c *Common) GetTCPStrategy() {
	if tcpStrategy := c.ParsedURL.Query().Get("notcp"); tcpStrategy != "" {
		c.DisableTCP = tcpStrategy
	} else {
		c.DisableTCP = DefaultTCPStrategy
	}
}

// GetUDPStrategy reads the "noudp" query parameter. "1" suppresses the UDP data path entirely,
// leaving only TCP active. Used to disable UDP tunneling when only TCP is desired.
func (c *Common) GetUDPStrategy() {
	if udpStrategy := c.ParsedURL.Query().Get("noudp"); udpStrategy != "" {
		c.DisableUDP = udpStrategy
	} else {
		c.DisableUDP = DefaultUDPStrategy
	}
}

// InitConfig orchestrates all configuration parsers in the correct dependency order.
// Must be called once after creating a Common instance with a parsed URL (NewCommon + URL assignment).
// GetAddress must run first (sets TunnelAddr, TargetAddrs, ServerName, ServerPort as side effects).
// All other getters run afterward in any order. Returns an error if address parsing, resolution, or validation fails.
func (c *Common) InitConfig() error {
	if err := c.GetAddress(); err != nil {
		return err
	}

	c.GetCoreType()
	c.GetDNSTTL()
	c.GetTunnelKey()
	c.GetPoolCapacity()
	c.GetServerName()
	c.GetLBStrategy()
	c.GetRunMode()
	c.GetPoolType()
	c.GetDialerIP()
	c.GetReadTimeout()
	c.GetRateLimit()
	c.GetSlotLimit()
	c.GetProxyProtocol()
	c.GetBlockProtocol()
	c.GetTCPStrategy()
	c.GetUDPStrategy()

	return nil
}
