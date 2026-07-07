// address.go provides DNS caching, address resolution helpers, target rotation,
// and the outbound dial functions used across the tunnel data paths.
package common

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Resolve resolves the given address string to both TCP and UDP net.Addr values, caching the result
// for DNSCacheTTL duration to avoid repeated lookups on hot paths. Expired cache entries are evicted
// and re-resolved on demand. Returns the resolved address for the requested network ("tcp" or "udp"),
// or an error if resolution fails. Cache hits are very fast; misses trigger DNS resolution.
func (c *Common) Resolve(network, address string) (any, error) {
	now := time.Now()

	if val, ok := c.DNSCacheEntries.Load(address); ok {
		entry := val.(*DnsCacheEntry)
		if now.Before(entry.ExpiredAt) {
			if network == "tcp" {
				return entry.TCPAddr, nil
			}
			return entry.UDPAddr, nil
		}
		c.DNSCacheEntries.Delete(address)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("Resolve: resolveTCPAddr failed: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("Resolve: resolveUDPAddr failed: %w", err)
	}

	entry := &DnsCacheEntry{
		TCPAddr:   tcpAddr,
		UDPAddr:   udpAddr,
		ExpiredAt: now.Add(c.DNSCacheTTL),
	}
	c.DNSCacheEntries.LoadOrStore(address, entry)

	if network == "tcp" {
		return tcpAddr, nil
	}
	return udpAddr, nil
}

// ClearCache removes all entries from the DNS cache by iterating and deleting each cached entry.
// Called during Stop() to release memory and ensure stale entries are not used if the tunnel is restarted.
// Safe to call multiple times (subsequent calls are no-ops).
func (c *Common) ClearCache() {
	c.DNSCacheEntries.Range(func(key, value any) bool {
		c.DNSCacheEntries.Delete(key)
		return true
	})
}

// ResolveAddr resolves a host:port address for the given network ("tcp" or "udp").
// Bare IP addresses bypass the DNS cache and are resolved directly via net.ResolveTCPAddr/net.ResolveUDPAddr.
// Hostname-based addresses are resolved through the DNS cache via Resolve, supporting dynamic updates via TTL expiry.
// Returns an error if the address format is invalid or resolution fails.
func (c *Common) ResolveAddr(network, address string) (any, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("ResolveAddr: invalid address %s: %w", address, err)
	}

	if host == "" || net.ParseIP(host) != nil {
		if network == "tcp" {
			return net.ResolveTCPAddr("tcp", address)
		}
		return net.ResolveUDPAddr("udp", address)
	}

	return c.Resolve(network, address)
}

// ResolveTarget re-resolves the target address at index idx through the DNS cache.
// On error, it falls back to the pre-resolved address stored during initialization (TargetTCPAddrs/TargetUDPAddrs).
// Returns an error if the index is out of range. Used to support dynamic target address updates.
func (c *Common) ResolveTarget(network string, idx int) (any, error) {
	if idx < 0 || idx >= len(c.TargetAddrs) {
		return nil, fmt.Errorf("ResolveTarget: index %d out of range", idx)
	}

	addr, err := c.ResolveAddr(network, c.TargetAddrs[idx])
	if err != nil {
		if network == "tcp" {
			return c.TargetTCPAddrs[idx], err
		}
		return c.TargetUDPAddrs[idx], err
	}
	return addr, nil
}

// GetTunnelTCPAddr re-resolves the tunnel address through the DNS cache and returns its TCP form.
// Falls back to the pre-cached TunnelTCPAddr on resolution failure, ensuring continuity.
// Used when fresh resolution is needed (e.g., periodic re-resolution for dynamic addresses).
func (c *Common) GetTunnelTCPAddr() (*net.TCPAddr, error) {
	addr, err := c.ResolveAddr("tcp", c.TunnelAddr)
	if err != nil {
		return c.TunnelTCPAddr, err
	}
	return addr.(*net.TCPAddr), nil
}

// GetTunnelUDPAddr re-resolves the tunnel address through the DNS cache and returns its UDP form.
// Falls back to the pre-cached TunnelUDPAddr on resolution failure, ensuring continuity.
// Used when fresh resolution is needed (e.g., periodic re-resolution for dynamic addresses).
func (c *Common) GetTunnelUDPAddr() (*net.UDPAddr, error) {
	addr, err := c.ResolveAddr("udp", c.TunnelAddr)
	if err != nil {
		return c.TunnelUDPAddr, err
	}
	return addr.(*net.UDPAddr), nil
}

// GetTargetAddrsString returns all resolved target TCP addresses formatted as a comma-separated string.
// Useful for logging and debugging to show which targets are currently configured.
// Returns empty string if no targets are configured.
func (c *Common) GetTargetAddrsString() string {
	addrs := make([]string, len(c.TargetTCPAddrs))
	for i, addr := range c.TargetTCPAddrs {
		addrs[i] = addr.String()
	}
	return strings.Join(addrs, ",")
}

// NextTargetIdx atomically increments the round-robin index, wraps it to stay within target range,
// and returns the index for the next target address. Used by round-robin load-balancing strategy ("0").
// Thread-safe via atomic operations; always succeeds.
func (c *Common) NextTargetIdx() int {
	if len(c.TargetTCPAddrs) <= 1 {
		return 0
	}
	return int((atomic.AddUint64(&c.TargetIdx, 1) - 1) % uint64(len(c.TargetTCPAddrs)))
}

// ProbeBestTarget concurrently TCP-pings all configured target addresses and selects the best one.
// Updates TargetIdx (atomically) to point to the lowest-latency target and updates BestLatency.
// Returns the best observed latency in milliseconds, or 0 if all targets are unreachable.
// Used by the latency-based load-balancing strategy ("1") to find the fastest target.
func (c *Common) ProbeBestTarget() int {
	count := len(c.TargetTCPAddrs)
	if count == 0 {
		return 0
	}

	type result struct{ idx, lat int }
	results := make(chan result, count)
	for i := range count {
		go func(idx int) { results <- result{idx, c.TcpPing(idx)} }(i)
	}

	bestIdx, bestLat := 0, 0
	for range count {
		if r := <-results; r.lat > 0 && (bestLat == 0 || r.lat < bestLat) {
			bestIdx, bestLat = r.idx, r.lat
		}
	}

	if bestLat > 0 {
		atomic.StoreUint64(&c.TargetIdx, uint64(bestIdx))
		atomic.StoreInt32(&c.BestLatency, int32(bestLat))
	}
	return bestLat
}

// TcpPing measures TCP round-trip latency (in milliseconds) to the target at index idx by attempting
// a TCP connection and timing how long it takes. Returns 0 on any failure (timeout, connection refused, etc.).
// Used by ProbeBestTarget to compare latencies across multiple targets.
func (c *Common) TcpPing(idx int) int {
	addr, _ := c.ResolveTarget("tcp", idx)
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		start := time.Now()
		if conn, err := net.DialTimeout("tcp", tcpAddr.String(), ReportInterval); err == nil {
			conn.Close()
			return int(time.Since(start).Milliseconds())
		}
	}
	return 0
}

// GetDialFunc returns a dial function for the given network and timeout that respects DialerIP binding.
// When DialerIP is "auto", the OS chooses the source address. When DialerIP is a specific IP, the returned
// function binds outbound connections to that IP and validates that the IP matches the expected address family
// (IPv4 vs IPv6) based on DialerIPv6. If the IP is invalid or mismatched, it falls back to default dialing.
// The returned function signature is func(string) (net.Conn, error) suitable for net.Dialer.Dial.
func (c *Common) GetDialFunc(network string, timeout time.Duration) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: timeout}

		if c.DialerIP == DefaultDialerIP {
			return dialer.Dial(network, addr)
		}

		parsedIP := net.ParseIP(c.DialerIP)
		if parsedIP == nil {
			return dialer.Dial(network, addr)
		}

		if c.DialerIPv6 != (parsedIP.To4() == nil) {
			return nil, fmt.Errorf("GetDialFunc: dialer IP %s mismatches expected address family", c.DialerIP)
		}

		if network == "tcp" {
			dialer.LocalAddr = &net.TCPAddr{IP: parsedIP}
		} else {
			dialer.LocalAddr = &net.UDPAddr{IP: parsedIP}
		}

		conn, err := dialer.Dial(network, addr)
		if err != nil {
			return nil, fmt.Errorf("GetDialFunc: failed to dial with IP %s: %w", c.DialerIP, err)
		}

		return conn, nil
	}
}

// DialWithRotation dials a target connection using the configured load-balancing strategy:
//   - "0" (round-robin): increments the index on every call, cycling through targets sequentially
//   - "1" (latency-best): uses the index last set by ProbeBestTarget, sticking with lowest latency
//   - "2" (failover): sticks to the primary target until FallbackInterval elapses, then resets to try primary again
//
// On failure of the initially chosen target, it walks through remaining addresses in order.
// Returns the first successful connection or an error wrapping the last failure.
// Used for all outbound tunnel dials to support various load-balancing and failover strategies.
func (c *Common) DialWithRotation(network string, timeout time.Duration) (net.Conn, error) {
	addrCount := len(c.TargetAddrs)

	getAddr := func(i int) string {
		addr, _ := c.ResolveTarget(network, i)
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.String()
		}
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			return udpAddr.String()
		}
		return ""
	}

	tryDial := c.GetDialFunc(network, timeout)

	if addrCount == 1 {
		if addr := getAddr(0); addr != "" {
			return tryDial(addr)
		}
		return nil, fmt.Errorf("DialWithRotation: invalid target address")
	}

	var startIdx int
	switch c.LBStrategy {
	case "1":
		startIdx = int(atomic.LoadUint64(&c.TargetIdx) % uint64(addrCount))
	case "2":
		now := uint64(time.Now().UnixNano())
		last := atomic.LoadUint64(&c.LastFallback)
		if now-last > uint64(FallbackInterval) {
			atomic.StoreUint64(&c.LastFallback, now)
			atomic.StoreUint64(&c.TargetIdx, 0)
		}
		startIdx = int(atomic.LoadUint64(&c.TargetIdx) % uint64(addrCount))
	default:
		startIdx = c.NextTargetIdx()
	}

	var lastErr error
	for i := range addrCount {
		targetIdx := (startIdx + i) % addrCount
		addr := getAddr(targetIdx)
		if addr == "" {
			continue
		}
		conn, err := tryDial(addr)
		if err == nil {
			if i > 0 && (c.LBStrategy == "1" || c.LBStrategy == "2") {
				atomic.StoreUint64(&c.TargetIdx, uint64(targetIdx))
			}
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("DialWithRotation: all %d targets failed: %w", addrCount, lastErr)
}
