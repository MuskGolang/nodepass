// types.go defines all shared data structures for the master package:
// Master, Instance, Meta, Peer, log writer, event, system info, MCP, and REST types.
package master

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// Master is the management-plane controller. It embeds common.Common for
// shared networking utilities and maintains a registry of running tunnel
// Instances. It exposes HTTP endpoints for REST and MCP management.
//
// The Master manages the lifecycle of tunnel instances, provides REST and MCP APIs,
// persists state to disk, broadcasts events via SSE, and performs periodic maintenance.
// All instances are stored in a thread-safe sync.Map for concurrent access. The Master
// can be configured with mTLS for secure communication with clients. State is persisted
// using GOB serialization to allow recovery from crashes. Background tasks run periodically
// to backup state, clean up duplicates, and restart failed instances.
type Master struct {
	common.Common
	MID           string              // unique master instance identifier
	Alias         string              // human-readable name
	Prefix        string              // URL prefix for all API routes
	Version       string              // build version string
	Hostname      string              // public hostname used in generated configs
	LogLevel      string              // current log level ("debug", "info", etc.)
	CrtPath       string              // path to TLS certificate for mTLS
	KeyPath       string              // path to TLS private key for mTLS
	Instances     sync.Map            // id → *Instance for all managed tunnels
	Server        *http.Server        // HTTP/HTTPS API server
	MTLSConfig    *tls.Config         // mTLS config for the management interface
	MasterURL     *url.URL            // URL advertised to clients for self-registration
	StatePath     string              // filesystem path for persistent state file
	StateMu       sync.Mutex          // guards state file I/O
	Subscribers   sync.Map            // SSE subscribers: id → http.ResponseWriter
	NotifyChannel chan *InstanceEvent // inbound instance status events
	TCPingSem     chan struct{}       // semaphore limiting concurrent TCPing operations
	StartTime     time.Time           // when this Master instance started
	PeriodicDone  chan struct{}       // closed when background periodic tasks finish
}

// Instance represents a single managed tunnel (client or server). It is
// serialised to/from the state file and returned by the REST/MCP APIs.
// Runtime-only fields (Cmd, Stopped, CancelFunc) are not persisted.
//
// Exported fields are serialized to JSON and GOB for API responses and state persistence.
// Metrics (Mode, Ping, Pool, TCPS/UDPS, TCPRX/TCPTX/UDPRX/UDPTX) are updated from
// CHECK_POINT events parsed from instance log output. Traffic counters (TCPRX, etc.)
// are delta-based, calculated from base values and reset values to allow counters to wrap.
// Status can be "running", "stopped", or "error". Restart flag controls auto-restart behavior.
// Config is a complete URL with all parameters filled in from master defaults and instance
// settings, sent to clients for configuration. Runtime fields are re-initialized on load:
//   - cmd: The child process handle
//   - stopped: Channel signaling instance shutdown
//   - deleted: Flag indicating the instance is marked for removal
//   - cancelFunc: Function to cancel the process context
//   - lastCheckPoint: Timestamp of last CHECK_POINT event (for heartbeat detection)
type Instance struct {
	ID             string `json:"id"`
	Alias          string `json:"alias"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	URL            string `json:"url"`
	Config         string `json:"config"`
	Restart        bool   `json:"restart"`
	Meta           Meta   `json:"meta"`
	Mode           int32  `json:"mode"`
	Ping           int32  `json:"ping"`
	Pool           int32  `json:"pool"`
	TCPS           int32  `json:"tcps"`
	UDPS           int32  `json:"udps"`
	TCPRX          uint64 `json:"tcprx"`
	TCPTX          uint64 `json:"tcptx"`
	UDPRX          uint64 `json:"udprx"`
	UDPTX          uint64 `json:"udptx"`
	tcpRXBase      uint64
	tcpTXBase      uint64
	udpRXBase      uint64
	udpTXBase      uint64
	tcpRXReset     uint64
	tcpTXReset     uint64
	udpRXReset     uint64
	udpTXReset     uint64
	cmd            *exec.Cmd
	stopped        chan struct{}
	deleted        bool
	cancelFunc     context.CancelFunc
	lastCheckPoint time.Time
}

// Meta carries optional peer-linkage and free-form tag metadata for an Instance.
//
// Peer allows associating an instance with its remote counterpart (the server paired with
// a client instance, or vice versa) for coordination and management. The peer reference is
// bidirectional but manually managed (updating one instance doesn't auto-update the other).
// Tags are arbitrary key-value pairs for user-defined metadata (max 256 chars each).
// Both fields are serialized to JSON and persisted in the state file.
type Meta struct {
	Peer Peer              `json:"peer"`
	Tags map[string]string `json:"tags"`
}

// Peer identifies the paired remote endpoint (server for a client instance,
// or client for a server instance) registered in the same Master.
//
// SID is the Service/Instance ID of the peer instance. Type identifies the peer's type
// ("client" or "server"), and Alias is a human-readable name for the peer (replicated
// from the peer instance for convenience). These fields are optional and user-managed.
type Peer struct {
	SID   string `json:"sid"`
	Type  string `json:"type"`
	Alias string `json:"alias"`
}

// InstanceLogWriter is an io.Writer that captures child-process log output,
// updates instance metric fields from CHECK_POINT events, and tees output to
// the underlying Target writer (usually os.Stdout).
//
// Implements the io.Writer interface to be used as stdout/stderr for child processes.
// Each Write call scans for CHECK_POINT log lines (format: CHECK_POINT|MODE=...|PING=...|...)
// and extracts metrics into the instance. Non-CHECK_POINT lines are logged with the
// instance ID appended. Error lines ("Server error:", "Client error:") update instance
// status to "error". All updates trigger SSE events to notify subscribers. The Target
// writer allows logs to be simultaneously written to stdout or a file for debugging.
type InstanceLogWriter struct {
	InstanceID string
	Instance   *Instance
	Target     io.Writer
	Master     *Master
	CheckPoint *regexp.Regexp
}

// InstanceEvent is the payload sent over the SSE stream when an instance
// status, metric, or log line changes.
//
// Type categorizes the event: "initial" (initial state on SSE connection), "create" (new instance),
// "update" (status/metric change), "delete" (instance removed), "log" (new log line), or
// "shutdown" (master shutting down). Time records when the event occurred. Instance is the
// current state snapshot at the time of the event. Logs contains a single log line if Type is
// "log"; for other types, it is empty. These events are JSON-serialized and sent to all
// connected SSE subscribers in real-time.
type InstanceEvent struct {
	Type     string    `json:"type"`
	Time     time.Time `json:"time"`
	Instance *Instance `json:"instance"`
	Logs     string    `json:"logs"`
}

// SystemInfo holds system resource metrics including CPU, memory, disk, and network statistics.
//
// Collected by GetLinuxSysInfo from /proc filesystem on Linux systems. CPU is a percentage
// (0-100) calculated from /proc/stat over a 100ms sample period. MemTotal and MemUsed are
// in bytes from /proc/meminfo. SwapTotal/SwapUsed are swap statistics. NetRX/NetTX are
// bytes transmitted/received on physical network interfaces (excluding virtual interfaces).
// DiskR/DiskW are bytes read/written to physical disks (excluding virtual block devices).
// SysUp is system uptime in seconds from /proc/uptime. Fields are populated only on Linux;
// on other platforms, they default to 0 or -1.
type SystemInfo struct {
	CPU       int    `json:"cpu"`
	MemTotal  uint64 `json:"mem_total"`
	MemUsed   uint64 `json:"mem_used"`
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
	NetRX     uint64 `json:"netrx"`
	NetTX     uint64 `json:"nettx"`
	DiskR     uint64 `json:"diskr"`
	DiskW     uint64 `json:"diskw"`
	SysUp     uint64 `json:"sysup"`
}

// TCPingResult represents the result of a TCP connectivity test including latency and error information.
//
// Target is the address that was tested (host:port). Connected indicates whether the TCP
// connection succeeded. Latency is the time in milliseconds to establish the connection
// (0 if connection failed). Error is a pointer to an error message (nil if successful,
// contains "too many requests" if semaphore full, or the connection error otherwise).
// Used by the TCPing REST endpoint and MCP tool for network diagnostics.
type TCPingResult struct {
	Target    string  `json:"target"`
	Connected bool    `json:"connected"`
	Latency   int64   `json:"latency"`
	Error     *string `json:"error"`
}

// MCPRequest is the JSON-RPC 2.0 request envelope for the MCP API.
//
// JSONRPC must be "2.0" (validated by HandleMCP). ID is an optional request identifier
// (can be a string, number, or omitted for notifications). Method specifies the RPC
// method to call (e.g., "initialize", "tools/list", "tools/call"). Params contains the
// method parameters as raw JSON (decoded into specific types by each handler). Used by
// Claude and other MCP clients to request tool execution on the master.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse is the JSON-RPC 2.0 response envelope. Exactly one of Result
// or Error is populated.
//
// JSONRPC is always "2.0". ID echoes the request ID (omitted for notifications).
// Result contains the method's return value if successful; Error is populated if the
// call failed. Standard error codes follow JSON-RPC 2.0 spec:
//   - -32700: Parse error
//   - -32600: Invalid Request
//   - -32601: Method not found
//   - -32602: Invalid params
//   - -32603: Internal error
//
// Data is optional context for the error (e.g., field name that failed validation).
type MCPResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data,omitempty"`
	} `json:"error,omitempty"`
}

// MCPToolCallParams contains the parameters for an MCP tool call request.
//
// Name is the name of the tool to execute (e.g., "create_instance", "control_instance").
// Arguments is a map of parameter names to values, with types determined by the tool's
// input schema. Unknown or invalid argument types are handled gracefully by the handlers
// (type assertions with defaults or error returns). Decoded from the MCPRequest.Params
// field by HandleMCPToolsCall.
type MCPToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}
