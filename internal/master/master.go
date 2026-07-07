// Package master implements the nodepass management plane. It exposes a REST
// API and an MCP (Model Context Protocol) JSON-RPC endpoint for creating,
// configuring, starting, and monitoring tunnel instances. Each instance runs
// as a child process with its own client or server configuration.
package master

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// Master API path, version, and operational constants.
const (
	// DefaultAPIPath is the default base path for REST API endpoints (/api).
	// Can be overridden via the URL path parameter when starting the master.
	DefaultAPIPath = "/api"

	// OpenAPIVersion is the REST API version suffix (v1), appended to the API prefix
	// to form the full API path (e.g., /api/v1/instances).
	OpenAPIVersion = "v1"

	// NextMCPVersion is the URL path suffix for the MCP JSON-RPC 2.0 endpoint (v2),
	// typically served at /api/v2 for future protocol upgrades.
	NextMCPVersion = "v2"

	// MCPVersion is the Model Context Protocol version advertised to clients in the
	// "initialize" handshake response, following the format YYYY-MM-DD.
	MCPVersion = "2025-11-25"

	// StateFilePath is the relative directory name where the master state file is stored
	// within the binary's directory (gob/).
	StateFilePath = "gob"

	// StateFileName is the filename of the master's persisted instance registry
	// using GOB serialization (nodepass.gob).
	StateFileName = "nodepass.gob"

	// ExportFileName is the filename for exported instance configurations in JSON format
	// (nodepass.json), used by export_instances and import_instances MCP tools.
	ExportFileName = "nodepass.json"

	// SSERetryTime is the retry interval in milliseconds (3000ms = 3s) sent to SSE clients
	// in the "retry:" field, instructing them to reconnect if the connection is lost.
	SSERetryTime = 3000

	// APIKeyID is a special instance ID (****) reserved for storing the master's API key
	// and Master ID. It's not a real instance and is not included in instance lists.
	APIKeyID = "********"

	// PingSemLimit is the maximum number of concurrent TCP ping operations (10),
	// enforced via a semaphore to prevent resource exhaustion on high-load systems.
	PingSemLimit = 10

	// BaseDuration is the base wait time (100ms) used for delays between operations:
	// - Between stopping and restarting instances during restart action
	// - Between auto-starting instances during state load
	// - In GetLinuxSysInfo for CPU usage delta calculation
	BaseDuration = 100 * time.Millisecond

	// GracefulTimeout is the maximum time (5s) allowed for graceful process shutdown
	// (SIGTERM/SIGINT) before sending SIGKILL force termination.
	GracefulTimeout = 5 * time.Second

	// MaxValueLen is the maximum length (256 characters) for string fields in the API,
	// including instance aliases, peer information, tag keys/values, and master alias,
	// to prevent unbounded memory usage from malicious or misconfigured clients.
	MaxValueLen = 256
)

// NewMaster constructs and returns a Master from a parsed URL, TLS config,
// logger, and binary version string. It resolves the listen address, derives
// the API prefix and MID hostname, loads persisted state, and starts the SSE
// event dispatcher goroutine.
//
// The URL is parsed to extract the host and port for listening, and optionally
// uses the TLS ServerName for the public hostname. The path becomes the API prefix
// (defaulting to /api if not specified). The master binary's directory is used to
// locate the state file. A notification channel and semaphore are initialized
// for event broadcasting and TCP ping operations. The master startup time is
// recorded for uptime calculations.
//
// Parameters:
//   - parsedURL: The parsed URL containing host, port, path, and query parameters
//   - tlsCode: TLS mode code ("0" for none, "1" for self-signed, "2" for custom certs)
//   - tlsConfig: Optional TLS configuration for HTTPS
//   - logger: Logger instance for error and info messages
//   - version: Build/binary version string
//
// Returns a new Master instance or an error if address resolution fails.
func NewMaster(parsedURL *url.URL, tlsCode string, tlsConfig *tls.Config, logger *common.Logger, version string) (*Master, error) {
	host, err := net.ResolveTCPAddr("tcp", parsedURL.Host)
	if err != nil {
		return nil, fmt.Errorf("NewMaster: resolve host failed: %w", err)
	}

	var hostname string
	if tlsConfig != nil && tlsConfig.ServerName != "" {
		hostname = tlsConfig.ServerName
	} else {
		hostname = parsedURL.Hostname()
	}

	prefix := parsedURL.Path
	if prefix == "" || prefix == "/" {
		prefix = DefaultAPIPath
	} else {
		prefix = strings.TrimRight(prefix, "/")
	}

	execPath, _ := os.Executable()
	baseDir := filepath.Dir(execPath)

	master := &Master{
		Common:        common.NewCommon(logger, nil),
		Prefix:        fmt.Sprintf("%s/%s", prefix, OpenAPIVersion),
		Version:       version,
		LogLevel:      parsedURL.Query().Get("log"),
		CrtPath:       parsedURL.Query().Get("crt"),
		KeyPath:       parsedURL.Query().Get("key"),
		Hostname:      hostname,
		MTLSConfig:    tlsConfig,
		MasterURL:     parsedURL,
		StatePath:     filepath.Join(baseDir, StateFilePath, StateFileName),
		NotifyChannel: make(chan *InstanceEvent, common.SemaphoreLimit),
		TCPingSem:     make(chan struct{}, PingSemLimit),
		StartTime:     time.Now(),
		PeriodicDone:  make(chan struct{}),
	}
	master.TLSCode = tlsCode
	master.TunnelTCPAddr = host

	master.LoadState()

	go master.StartEventDispatcher()

	return master, nil
}

// Run starts the master: loads or generates the API key, registers HTTP routes
// (both API-key-protected and public), starts the HTTP(S) server and periodic
// background tasks, and blocks until SIGINT/SIGTERM, then gracefully shuts down.
//
// Creates or loads the API key and Master ID (MID) from the instance registry.
// If no API key exists, one is generated and persisted. Protected endpoints require
// the X-API-Key header; public endpoints (OpenAPI spec and docs) are accessible
// without authentication. All HTTP responses include CORS headers. The HTTP server
// is started in a separate goroutine (using TLS if configured). Background tasks
// run concurrently for periodic maintenance. The function blocks until receiving
// SIGINT or SIGTERM, then initiates graceful shutdown with a timeout.
func (m *Master) Run() {
	m.Logger.Info("Master started: %v%v", m.TunnelTCPAddr, m.Prefix)
	apiKey, ok := m.FindInstance(APIKeyID)
	if !ok {
		apiKey = &Instance{
			ID:     APIKeyID,
			URL:    GenerateAPIKey(),
			Config: GenerateMID(),
			Meta:   Meta{Tags: make(map[string]string)},
		}
		m.Instances.Store(APIKeyID, apiKey)
		m.SaveState()
		fmt.Printf("%s  \033[32mINFO\033[0m  API Key created: %v\n", time.Now().Format("2006-01-02 15:04:05.000"), apiKey.URL)
	} else {
		m.Alias = apiKey.Alias

		if apiKey.Config == "" {
			apiKey.Config = GenerateMID()
			m.Instances.Store(APIKeyID, apiKey)
			m.SaveState()
			m.Logger.Info("Master ID created: %v", apiKey.Config)
		}
		m.MID = apiKey.Config

		fmt.Printf("%s  \033[32mINFO\033[0m  API Key loaded: %v\n", time.Now().Format("2006-01-02 15:04:05.000"), apiKey.URL)
	}

	mux := http.NewServeMux()

	protectedEndpoints := map[string]http.HandlerFunc{
		fmt.Sprintf("%s/instances", m.Prefix):  m.HandleInstances,
		fmt.Sprintf("%s/instances/", m.Prefix): m.HandleInstanceDetail,
		fmt.Sprintf("%s/events", m.Prefix):     m.HandleSSE,
		fmt.Sprintf("%s/info", m.Prefix):       m.HandleInfo,
		fmt.Sprintf("%s/tcping", m.Prefix):     m.HandleTCPing,

		strings.TrimSuffix(m.Prefix, "/"+OpenAPIVersion) + "/" + NextMCPVersion: m.HandleMCP,
	}

	publicEndpoints := map[string]http.HandlerFunc{
		fmt.Sprintf("%s/openapi.json", m.Prefix): m.HandleOpenAPISpec,
		fmt.Sprintf("%s/docs", m.Prefix):         m.HandleSwaggerUI,
	}

	apiKeyMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			SetCorsHeaders(w)
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			apiKeyInstance, keyExists := m.FindInstance(APIKeyID)
			if keyExists && apiKeyInstance.URL != "" {
				reqAPIKey := r.Header.Get("X-API-Key")
				if reqAPIKey == "" {
					HTTPError(w, "Unauthorized: API key required", http.StatusUnauthorized)
					return
				}

				if reqAPIKey != apiKeyInstance.URL {
					HTTPError(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
					return
				}
			}

			next(w, r)
		}
	}

	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			SetCorsHeaders(w)
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next(w, r)
		}
	}

	for path, handler := range protectedEndpoints {
		mux.HandleFunc(path, apiKeyMiddleware(handler))
	}

	for path, handler := range publicEndpoints {
		mux.HandleFunc(path, corsMiddleware(handler))
	}

	m.Server = &http.Server{
		Addr:      m.TunnelTCPAddr.String(),
		ErrorLog:  m.Logger.StdLogger(),
		Handler:   mux,
		TLSConfig: m.MTLSConfig,
	}

	go func() {
		var err error
		if m.MTLSConfig != nil {
			err = m.Server.ListenAndServeTLS("", "")
		} else {
			err = m.Server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			m.Logger.Error("Run: listen failed: %v", err)
		}
	}()

	go m.StartPeriodicTasks()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-ctx.Done()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), common.ShutdownTimeout)
	defer cancel()
	if err := m.MasterShutdown(shutdownCtx); err != nil {
		m.Logger.Error("Master shutdown error: %v", err)
	} else {
		m.Logger.Info("Master shutdown complete")
	}
}

// MasterShutdown tears down all master resources: closes SSE connections,
// stops all child-process instances, closes the notify channel, persists
// state, and shuts down the HTTP server — all bounded by ctx.
//
// Performs an ordered shutdown: first notifies all SSE subscribers, then
// gracefully stops each running instance in parallel using StopInstance.
// The notify channel is closed to stop the event dispatcher. The instance
// registry is persisted to disk (GOB format) for crash recovery. Finally,
// the HTTP server is shut down with the given context deadline. Any errors
// during persistence or server shutdown are logged but do not prevent
// continuation of the shutdown sequence.
//
// Parameters:
//   - ctx: Context with timeout controlling the maximum shutdown duration
//
// Returns an error from the underlying CommonShutdown if the shutdown fails.
func (m *Master) MasterShutdown(ctx context.Context) error {
	return m.CommonShutdown(ctx, func() {
		m.ShutdownSSEConnections()

		var wg sync.WaitGroup
		m.Instances.Range(func(key, value any) bool {
			instance := value.(*Instance)
			if instance.Status != "stopped" && instance.cmd != nil && instance.cmd.Process != nil {
				wg.Add(1)
				go func(inst *Instance) {
					defer wg.Done()
					m.StopInstance(inst)
				}(instance)
			}
			return true
		})

		wg.Wait()

		close(m.PeriodicDone)

		close(m.NotifyChannel)

		if err := m.SaveState(); err != nil {
			m.Logger.Error("MasterShutdown: save gob failed: %v", err)
		} else {
			m.Logger.Info("Instances saved: %v", m.StatePath)
		}

		if err := m.Server.Shutdown(ctx); err != nil {
			m.Logger.Error("MasterShutdown: api shutdown error: %v", err)
		}
	})
}
