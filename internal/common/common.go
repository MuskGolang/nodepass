// Package common provides shared core components and utilities used across the nodepass system.
// It includes configuration management, network address resolution, protocol detection,
// encryption/authentication, and common data structures for servers, clients, and masters.
package common

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/NodePassProject/nodepass/internal/transport"
)

// Default configuration values used when URL query parameters are absent.
const (
	// ContextCheckInterval is the polling interval for checking context cancellation in blocking I/O operations.
	// Used to detect shutdown signals without blocking indefinitely on network reads/writes.
	ContextCheckInterval = 50 * time.Millisecond

	// DefaultDNSTTL is the time-to-live duration for cached DNS resolution results. Addresses are re-resolved
	// after this TTL expires to support dynamic target address changes and prevent stale DNS data.
	DefaultDNSTTL = 5 * time.Minute

	// DefaultMinPool is the minimum number of pre-established tunnel connections to maintain in the connection pool.
	// The pool manager will continuously dial new connections until this threshold is reached.
	DefaultMinPool = 64

	// DefaultMaxPool is the maximum number of tunnel connections allowed in the pool. Once this limit is reached,
	// the pool stops accepting new connections until existing ones are released.
	DefaultMaxPool = 1024

	// DefaultServerName is the default TLS Server Name Indication (SNI) hostname when not explicitly provided.
	// Set to "none" to indicate either IP-based connection or omission of SNI field in the TLS ClientHello.
	DefaultServerName = "none"

	// DefaultLBStrategy specifies the default load-balancing strategy when multiple target addresses are available:
	// "0" = round-robin (sequential cycling), "1" = latency-based (lowest response time), "2" = failover (primary until timeout).
	DefaultLBStrategy = "0"

	// DefaultRunMode specifies the default operational mode: "0" = auto-detect (single vs. pool based on config),
	// "1" = single-connection mode (no pool, fresh dial per client), "2" = always use connection pool.
	DefaultRunMode = "0"

	// DefaultPoolType specifies the default tunnel pool backend:
	// "0" = TCP, "1" = QUIC, "2" = WebSocket, "3" = HTTP/2.
	DefaultPoolType = "0"

	// DefaultDialerIP specifies the default source IP for outbound tunnel connections. "auto" means the OS selects
	// the source address using the system's default route; can be overridden with a specific IPv4 or IPv6 address.
	DefaultDialerIP = "auto"

	// DefaultReadTimeout is the default per-connection read deadline (0 = no deadline, infinite wait).
	// Can be overridden per tunnel via URL parameters to enforce maximum time for receiving data on a connection.
	DefaultReadTimeout = 0 * time.Second

	// DefaultRateLimit is the default token-bucket rate limit in bytes per second (0 = unlimited).
	// When enabled (non-zero), controls maximum throughput on tunnel data flows to prevent link saturation.
	DefaultRateLimit = 0

	// DefaultSlotLimit is the maximum number of concurrent connection slots that can be allocated.
	// Prevents unbounded resource allocation when handling many simultaneous tunnels and connections.
	DefaultSlotLimit = 65536

	// DefaultProxyProtocol specifies whether to emit PROXY Protocol v1 headers on outbound connections:
	// "0" = disabled (default), "1" = enabled. Required by some upstream proxies or load balancers that expect HAProxy-compatible headers.
	DefaultProxyProtocol = "0"

	// DefaultBlockProtocol is a bitmask string controlling which application protocols to block at the connection boundary:
	// "1" = block SOCKS4/SOCKS5, "2" = block HTTP CONNECT, "4" = block TLS ClientHello. Multiple flags can be combined.
	DefaultBlockProtocol = "0"

	// DefaultTCPStrategy is reserved for future TCP-specific strategy selection. Currently unused but retained for forward compatibility.
	DefaultTCPStrategy = "0"

	// DefaultUDPStrategy is reserved for future UDP-specific strategy selection. Currently unused but retained for forward compatibility.
	DefaultUDPStrategy = "0"
)

// Environment-tunable runtime parameters. All can be overridden via environment variables with the NP_ prefix.
// Example: export NP_TCP_DATA_BUF_SIZE=32768 to change TCP buffer size at runtime.
var (
	// SemaphoreLimit is the maximum buffer depth for SignalChan and WriteChan. Controls how many signals
	// can be queued before the sender blocks. Configurable via NP_SEMAPHORE_LIMIT environment variable.
	SemaphoreLimit = GetEnvAsInt("NP_SEMAPHORE_LIMIT", 65536)

	// TCPDataBufSize is the size in bytes of each TCP read/write buffer allocated from the buffer pool.
	// Larger values reduce syscalls but increase memory overhead. Configurable via NP_TCP_DATA_BUF_SIZE.
	TCPDataBufSize = GetEnvAsInt("NP_TCP_DATA_BUF_SIZE", 16384)

	// UDPDataBufSize is the size in bytes of each UDP read/write buffer allocated from the buffer pool.
	// Must be large enough to accommodate the maximum UDP datagram size. Configurable via NP_UDP_DATA_BUF_SIZE.
	UDPDataBufSize = GetEnvAsInt("NP_UDP_DATA_BUF_SIZE", 16384)

	// HandshakeTimeout is the maximum duration allowed for the initial TLS and control-channel handshake.
	// Exceeded timeout aborts the tunnel initialization. Configurable via NP_HANDSHAKE_TIMEOUT.
	HandshakeTimeout = GetEnvAsDuration("NP_HANDSHAKE_TIMEOUT", 5*time.Second)

	// TCPDialTimeout is the timeout for establishing outbound TCP connections to target addresses.
	// Exceeded timeout causes the dial to fail and fallback to the next target. Configurable via NP_TCP_DIAL_TIMEOUT.
	TCPDialTimeout = GetEnvAsDuration("NP_TCP_DIAL_TIMEOUT", 5*time.Second)

	// UDPDialTimeout is the timeout for establishing outbound UDP sockets to target addresses.
	// Exceeded timeout causes the dial to fail and fallback to the next target. Configurable via NP_UDP_DIAL_TIMEOUT.
	UDPDialTimeout = GetEnvAsDuration("NP_UDP_DIAL_TIMEOUT", 5*time.Second)

	// UDPReadTimeout is the read timeout for UDP sessions (both target-side and tunnel-side).
	// Exceeded timeout aborts the session and releases the UDP connection. Configurable via NP_UDP_READ_TIMEOUT.
	UDPReadTimeout = GetEnvAsDuration("NP_UDP_READ_TIMEOUT", 30*time.Second)

	// PoolGetTimeout is the timeout for retrieving a connection from the tunnel pool. Exceeded timeout returns
	// an error and causes the associated data transfer to fail. Configurable via NP_POOL_GET_TIMEOUT.
	PoolGetTimeout = GetEnvAsDuration("NP_POOL_GET_TIMEOUT", 5*time.Second)

	// MinPoolInterval is the minimum interval between pool expansion checks. Prevents rapid repeated dials
	// when the pool is below capacity. Configurable via NP_MIN_POOL_INTERVAL.
	MinPoolInterval = GetEnvAsDuration("NP_MIN_POOL_INTERVAL", 100*time.Millisecond)

	// MaxPoolInterval is the maximum interval between pool expansion checks. After inactivity, the pool waits
	// up to this duration before checking if more connections are needed. Configurable via NP_MAX_POOL_INTERVAL.
	MaxPoolInterval = GetEnvAsDuration("NP_MAX_POOL_INTERVAL", 1*time.Second)

	// ReportInterval is the frequency for emitting CHECK_POINT log events that include latency, slot counts,
	// and byte counters. Also used for health checks and pool flush rate-limiting. Configurable via NP_REPORT_INTERVAL.
	ReportInterval = GetEnvAsDuration("NP_REPORT_INTERVAL", 5*time.Second)

	// FallbackInterval is the duration before the failover load-balancing strategy resets back to the primary target.
	// After this interval, the primary target is retried even if it previously failed. Configurable via NP_FALLBACK_INTERVAL.
	FallbackInterval = GetEnvAsDuration("NP_FALLBACK_INTERVAL", 5*time.Minute)

	// ServiceCooldown is the duration to wait before attempting to restart a tunnel after graceful shutdown.
	// Allows time for cleanup, connection draining, and resource release. Configurable via NP_SERVICE_COOLDOWN.
	ServiceCooldown = GetEnvAsDuration("NP_SERVICE_COOLDOWN", 3*time.Second)

	// ShutdownTimeout is the maximum duration allowed for the Stop() method to complete. Exceeded timeout
	// indicates forceful shutdown may be needed. Configurable via NP_SHUTDOWN_TIMEOUT.
	ShutdownTimeout = GetEnvAsDuration("NP_SHUTDOWN_TIMEOUT", 5*time.Second)

	// ReloadInterval is the frequency for checking if the tunnel configuration has changed and needs reloading.
	// Used in daemon/continuous-run scenarios. Configurable via NP_RELOAD_INTERVAL.
	ReloadInterval = GetEnvAsDuration("NP_RELOAD_INTERVAL", 1*time.Hour)
)

// Config holds all configuration fields parsed from the tunnel URL. It is embedded in Common
// and populated by the InitConfig method, which runs all individual configuration parser functions
// in the correct dependency order. Configuration is read once at startup and is immutable afterward.
type Config struct {
	// ParsedURL is the parsed URL object (scheme://[user]@host:port/target?query) used to configure this instance.
	ParsedURL *url.URL

	// CoreType identifies the role of this instance: "client" (initiates tunnels) or "server" (accepts tunnel connections).
	CoreType string

	// RunMode specifies the operational mode: "0"=auto-detect (single for one target, pool for multiple),
	// "1"=single-connection (fresh dial per client, no pool), "2"=always use connection pool.
	RunMode string

	// DataFlow indicates the direction of target traffic: "+" (toward target) or "-" (toward tunnel).
	// Used to determine whether to forward client traffic to target ("+") or accept target responses ("-").
	DataFlow string

	// PoolType selects the transport backend used by the tunnel pool:
	// "0" = TCP, "1" = QUIC, "2" = WebSocket, "3" = HTTP/2.
	PoolType string

	// TLSCode enables optional TLS-specific features: "1" enables mutual certificate fingerprint verification
	// on the RAM-generated ephemeral certificates (TLS code-1 feature).
	TLSCode string

	// TunnelKey is the pre-shared key for XOR obfuscation of control-channel signals. Derived from URL username
	// if present, otherwise computed as FNV-1a hash of the tunnel port. Must match between client and server.
	TunnelKey string

	// TunnelAddr is the resolved host:port address of the tunnel endpoint (client connects to this, server listens on this).
	TunnelAddr string

	// TargetAddrs holds the raw target address strings as provided in the URL path (comma-separated, e.g. "10.0.1.1:443,10.0.1.2:443").
	TargetAddrs []string

	// ServerName is the TLS Server Name Indication (SNI) hostname sent in TLS ClientHello. Set to "none"
	// for IP-based connections or to explicitly omit SNI. Used for tunnel-endpoint TLS sessions.
	ServerName string

	// ServerPort is the port component extracted from TunnelAddr. Used for logging and port conflict detection.
	ServerPort string

	// ClientIP is the remote client IP address for informational purposes. Not actively used in tunneling logic.
	ClientIP string

	// DialerIP specifies the source IP for outbound tunnel connections. "auto" means the OS chooses the address;
	// otherwise must be a valid IPv4 or IPv6 address bound to the local machine. Validated during dial operations.
	DialerIP string

	// DialerIPv6 is true when DialerIP is an IPv6 address, false for IPv4. Used to validate address family consistency during dial operations.
	DialerIPv6 bool

	// LBStrategy specifies the load-balancing strategy when multiple targets are configured:
	// "0" = round-robin (sequential, stateless), "1" = latency-based (use lowest-latency target),
	// "2" = failover (primary until FallbackInterval elapses, then reset).
	LBStrategy string

	// DNSCacheTTL is the time-to-live duration for cached DNS resolution results. Expired entries are re-resolved.
	// Allows supporting dynamic target address changes without restarting the tunnel.
	DNSCacheTTL time.Duration

	// MinPoolCapacity is the minimum number of pre-established tunnel connections to maintain in the pool.
	// The pool manager continuously dials new connections until this threshold is reached.
	MinPoolCapacity int

	// MaxPoolCapacity is the maximum number of tunnel connections allowed in the pool. The pool stops accepting
	// new connections once this limit is reached until existing ones are released.
	MaxPoolCapacity int

	// ProxyProtocol controls PROXY Protocol v1 header emission: "0" = disabled (default),
	// "1" = enabled. Required by some upstream proxies or load balancers that expect HAProxy-compatible headers.
	ProxyProtocol string

	// BlockProtocol is a bitmask string controlling protocol blocking at the connection boundary:
	// "1" = block SOCKS4/SOCKS5, "2" = block HTTP CONNECT, "4" = block TLS ClientHello.
	// Multiple flags can be combined (e.g. "12" blocks SOCKS and HTTP).
	BlockProtocol string

	// BlockSOCKS is true when SOCKS4/SOCKS5 protocols should be detected and rejected (parsed from BlockProtocol).
	BlockSOCKS bool

	// BlockHTTP is true when HTTP CONNECT and plain HTTP protocols should be detected and rejected (parsed from BlockProtocol).
	BlockHTTP bool

	// BlockTLS is true when TLS ClientHello (HTTPS/TLS handshakes) should be detected and rejected (parsed from BlockProtocol).
	BlockTLS bool

	// DisableTCP is "1" to suppress the TCP tunnel entirely (only UDP active). "0" (default) enables TCP.
	DisableTCP string

	// DisableUDP is "1" to suppress the UDP tunnel entirely (only TCP active). "0" (default) enables UDP.
	DisableUDP string

	// RateLimit is the token-bucket rate limit in bytes per second. 0 = unlimited throughput.
	// When non-zero, controls maximum bandwidth on tunnel data flows to prevent link saturation.
	RateLimit int

	// ReadTimeout is the per-connection read deadline. 0 (default) disables read deadlines.
	// Non-zero values enforce maximum time for receiving data on a connection; exceeded timeout aborts the connection.
	ReadTimeout time.Duration
}

// Addrs holds resolved network addresses and load-balancer state. It is embedded in Common
// and populated by GetAddress during configuration and by Resolve/ResolveAddr during runtime as DNS entries expire.
// All address slices are populated together and remain synchronized.
type Addrs struct {
	// TunnelTCPAddr is the resolved TCP address of the tunnel endpoint (from TunnelAddr).
	// Cached during GetAddress and used as fallback if dynamic re-resolution fails.
	TunnelTCPAddr *net.TCPAddr

	// TunnelUDPAddr is the resolved UDP address of the tunnel endpoint (from TunnelAddr).
	// Cached during GetAddress and used as fallback if dynamic re-resolution fails.
	TunnelUDPAddr *net.UDPAddr

	// TargetTCPAddrs holds the resolved TCP addresses for each configured target (from TargetAddrs).
	// Populated during GetAddress from comma-separated target list. Used for TCP connections and probing.
	TargetTCPAddrs []*net.TCPAddr

	// TargetUDPAddrs holds the resolved UDP addresses for each configured target (from TargetAddrs).
	// Populated during GetAddress from comma-separated target list. Kept synchronized with TargetTCPAddrs.
	TargetUDPAddrs []*net.UDPAddr

	// TargetIdx is the current target index for load-balancing, accessed atomically.
	// Meaning depends on LBStrategy: round-robin (incremented each dial), latency-best (set by ProbeBestTarget),
	// or failover (reset after FallbackInterval).
	TargetIdx uint64

	// LastFallback is the timestamp (in nanoseconds, UnixNano) of the last failover reset.
	// Used by the "2" (failover) strategy to determine when to reset to the primary target.
	LastFallback uint64

	// BestLatency is the round-trip latency (in milliseconds) of the lowest-latency target, accessed atomically.
	// Updated by ProbeBestTarget when used with the "1" (latency-based) load-balancing strategy.
	BestLatency int32

	// DNSCacheEntries maps address strings to *DnsCacheEntry for caching resolved addresses.
	// Uses sync.Map for lock-free concurrent reads. Entries expire after DNSCacheTTL duration.
	DNSCacheEntries sync.Map
}

// Common holds all shared state for a tunnel endpoint (client or server) and is embedded directly
// into Client and Server structs. Each instance represents a single active tunnel with independent
// configuration, connections, and runtime state. Common must be created via NewCommon.
type Common struct {
	// Config embeds all parsed URL configuration (inherited by composition).
	Config

	// Addrs embeds all resolved network addresses and load-balancer state (inherited by composition).
	Addrs

	// Stats embeds atomic counters for TCP/UDP byte transfers, slot allocations, and error tracking.
	*transport.Stats

	// Buffers embeds the pooled byte-slice allocators for TCP and UDP read/write buffers.
	*transport.Buffers

	// Logger is the structured logger for this tunnel instance. Thread-safe, supports multiple log levels.
	Logger *Logger

	// TLSConfig holds the TLS configuration including the ephemeral self-signed certificate.
	// Nil indicates plaintext (no TLS wrapping). Generated once at init via NewTLSConfig.
	TLSConfig *tls.Config

	// TunnelListener is the local TCP listener that accepts incoming tunnel connections.
	// In client mode, this is bound to the tunnel address and receives client traffic.
	TunnelListener net.Listener

	// TargetListener is the local TCP listener that accepts incoming target connections.
	// In server mode (DataFlow "-"), this listens on the target address for inbound traffic.
	TargetListener *net.TCPListener

	// ControlConn is the dedicated control-channel connection (claimed with ID "00000000" from the pool).
	// Multiplexes inbound/outbound Signal messages for pool coordination, health checks, and TLS verification.
	ControlConn net.Conn

	// TunnelUDPConn is the tunnel-side UDP socket wrapped with statistics tracking and optional rate limiting.
	// In client mode, receives UDP from clients; in server mode, forwards UDP to targets.
	TunnelUDPConn *transport.StatConn

	// TargetUDPConn is the target-side UDP socket wrapped with statistics tracking and optional rate limiting.
	// In server mode, receives UDP from targets; in client mode, forwards UDP to tunnel endpoint.
	TargetUDPConn *transport.StatConn

	// TargetUDPSession maps session keys (client address strings) to net.Conn for active UDP flows.
	// Each unique client address gets a persistent UDP session to the target. Sessions are cleaned up on timeout.
	TargetUDPSession sync.Map

	// TunnelPool is the connection pool managing pre-established tunnel connections.
	// Implements TransportPool interface; clients retrieve connections by ID, servers add connections.
	TunnelPool TransportPool

	// RateLimiter is the token-bucket rate limiter for bandwidth control (nil when RateLimit == 0).
	// When configured, limits bytes/second throughput on data flows to prevent saturation.
	RateLimiter *transport.RateLimiter

	// BufReader is a buffered reader wrapping ControlConn for efficient line-buffered signal reception.
	// Used to read newline-delimited encoded signals from the remote peer.
	BufReader *bufio.Reader

	// SignalChan receives decoded Signal objects dispatched from TunnelQueue (pooled mode).
	// Buffered channel with capacity SemaphoreLimit to prevent deadlocks. Drained on Stop().
	SignalChan chan Signal

	// WriteChan queues encoded Signal bytes to be written to ControlConn by the writer goroutine.
	// Buffered channel with capacity SemaphoreLimit. Drained on Stop().
	WriteChan chan []byte

	// VerifyChan is closed/sent when TLS fingerprint verification succeeds (TLS code-1 feature).
	// Blocks TunnelLoop until verification completes or context is cancelled. Drained on Stop().
	VerifyChan chan struct{}

	// Ctx is the cancellation context for this tunnel run. Cancelled by calling Cancel() to initiate shutdown.
	// All goroutines poll Ctx.Done() to detect shutdown signals.
	Ctx context.Context

	// Cancel is the context cancellation function. Call to initiate graceful shutdown of this tunnel instance.
	// Cancelling Ctx causes all goroutines to exit; Stop() should be called afterward for cleanup.
	Cancel context.CancelFunc

	// HandshakeStart records the timestamp when the handshake sequence began (for latency measurement).
	// Logged when control connection is established to measure total tunnel setup time.
	HandshakeStart time.Time

	// CheckPoint records the timestamp of the last ping sent (for round-trip-time measurement).
	// Updated by HealthCheck before sending "ping" signals; used to measure RTT via "pong" response.
	CheckPoint time.Time
}

// NewCommon creates a Common instance wired with the given logger, TLS config, and pre-allocated
// channels and buffer pools. Caller must separately invoke InitConfig() to parse URL parameters,
// InitContext() to set up the cancellation context, and InitTunnelListener/InitTargetListener
// to set up the network listeners. The Stats and Buffers are allocated fresh for each instance.
func NewCommon(logger *Logger, tlsConfig *tls.Config) Common {
	return Common{
		Stats:      new(transport.Stats),                                 // allocate fresh stats counters
		Buffers:    transport.NewBuffers(TCPDataBufSize, UDPDataBufSize), // create buffer pools
		Logger:     logger,                                               // attach logger
		TLSConfig:  tlsConfig,                                            // attach TLS config
		SignalChan: make(chan Signal, SemaphoreLimit),                    // buffered signal queue
		WriteChan:  make(chan []byte, SemaphoreLimit),                    // buffered write queue
		VerifyChan: make(chan struct{}),                                  // unbuffered verification gate
	}
}

// DnsCacheEntry caches both the TCP and UDP resolved forms of a single hostname so that
// a single DNS lookup operation satisfies both protocol families. Entries are stored in Common.DNSCacheEntries
// and are looked up during address resolution via Resolve().
type DnsCacheEntry struct {
	// TCPAddr is the resolved TCP form of the hostname (host:port parsed to *net.TCPAddr).
	TCPAddr *net.TCPAddr

	// UDPAddr is the resolved UDP form of the hostname (host:port parsed to *net.UDPAddr).
	UDPAddr *net.UDPAddr

	// ExpiredAt is the timestamp when this entry becomes invalid and should be re-resolved.
	// Set to now + DNSCacheTTL when the entry is created. Entries are evicted on-demand after expiration.
	ExpiredAt time.Time
}

// ReaderConn wraps a net.Conn with a replacement Reader (usually a *bufio.Reader),
// allowing peeked bytes from protocol detection (DetectBlockProtocol) to be re-read as part
// of the connection stream. This ensures that bytes consumed during protocol detection are
// not lost and are properly replayed to the application layer.
type ReaderConn struct {
	// net.Conn is the underlying network connection (embedded).
	net.Conn

	// Reader is the replacement reader, typically a *bufio.Reader that has peeked at the connection bytes.
	// Reads are performed through this reader rather than directly on the connection.
	Reader io.Reader
}

// Read implements net.Conn.Read by reading from the replacement Reader instead of directly from
// the underlying connection. This ensures any peeked bytes from protocol detection are replayed
// correctly to the caller, preventing data loss during the protocol detection phase.
func (rc *ReaderConn) Read(b []byte) (int, error) {
	return rc.Reader.Read(b)
}

// TransportPool abstracts the connection pool interface used to manage pre-established tunnel connections.
// Implementations (e.g., client.Pool, server.Pool) maintain pooled connections, handle connection
// lifecycle, and provide thread-safe access via IncomingGet/OutgoingGet. Used in pooled ("pool") mode.
type TransportPool interface {
	// IncomingGet retrieves a connection from the incoming queue (server-side), assigning it a unique ID.
	// Returns (id, connection, error) or error if timeout expires before a connection is available.
	IncomingGet(timeout time.Duration) (string, net.Conn, error)

	// OutgoingGet retrieves a specific connection from the outgoing queue by ID (client-side).
	// Returns the connection or error if the ID is not found or timeout expires.
	OutgoingGet(id string, timeout time.Duration) (net.Conn, error)

	// Flush closes all connections in the pool and clears the queues, forcing re-establishment.
	// Used in response to health check failures or explicit flush signals.
	Flush()

	// Close closes all pool connections and resources, preventing further access.
	// Called during tunnel shutdown to clean up the pool.
	Close()

	// Ready returns true if the pool is initialized and accepting connections (minimum capacity reached).
	// Returns false during initialization or if pool is stopped.
	Ready() bool

	// Active returns the current number of active (alive, not idle) connections in the pool.
	// Used for monitoring and health check decisions.
	Active() int

	// Capacity returns the maximum number of connections allowed in the pool (from MaxPoolCapacity).
	// Used to enforce hard limits on pool growth.
	Capacity() int

	// Interval returns the current interval between pool expansion checks.
	// Starts at MinPoolInterval and gradually backs off toward MaxPoolInterval during idle periods.
	Interval() time.Duration

	// AddError increments the error counter. Called when a connection fails or data transfer is interrupted.
	// Used by HealthCheck to decide when to flush the pool.
	AddError()

	// ErrorCount returns the current error count for the pool.
	// When ErrorCount > Active()/2, a flush is triggered.
	ErrorCount() int

	// ResetError resets the error counter to zero. Called after a successful flush to start fresh error tracking.
	ResetError()
}

// Signal is the wire format for control messages exchanged over the control connection between
// client and server. Signals coordinate tunnel data transfers, health checks, TLS verification, and
// pool management. Each Signal is JSON-encoded, XOR-obfuscated with TunnelKey, base64-encoded,
// and newline-terminated before transmission. Received signals are decoded and dispatched by TunnelQueue.
type Signal struct {
	// ActionType specifies the action to perform. Valid values are:
	//   - "tcp": initiate a TCP data transfer (server sends to client)
	//   - "udp": initiate a UDP data transfer (server sends to client)
	//   - "verify": TLS certificate fingerprint verification (either side initiates)
	//   - "ping": health check request (server sends to client)
	//   - "pong": health check response (client sends to server)
	//   - "flush": request pool flush (server sends to client)
	ActionType string `json:"action"`

	// RemoteAddr is the originating client address (e.g., "192.168.1.100:54321") for TCP/UDP signals.
	// Included when the remote peer initiates a data transfer; omitted for control signals like ping/flush.
	RemoteAddr string `json:"remote,omitempty"`

	// PoolConnID is the unique identifier of the tunnel pool connection to be used for this transfer.
	// Assigned by the originating side when retrieving the connection from the pool. Special ID "00000000"
	// reserves the control connection. Omitted for control signals like ping/pong/flush.
	PoolConnID string `json:"id,omitempty"`

	// Fingerprint is the SHA-256 certificate fingerprint (as hex string) for TLS code-1 verification.
	// Included only in "verify" signals. Compared by the remote side to ensure mutual certificate match.
	Fingerprint string `json:"fp,omitempty"`
}
