// instance.go manages the lifecycle of nodepass child-process instances:
// starting, stopping, monitoring, URL generation, and configuration updates.
package master

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// FindInstance retrieves an instance from the master's instance map by ID.
// Returns the instance and a boolean indicating whether it was found.
//
// Performs a thread-safe lookup in the Instances sync.Map. The returned
// instance pointer should not be modified directly; use the update methods
// and re-store the instance in the map to ensure changes are persisted.
//
// Parameters:
//   - id: The unique instance identifier
//
// Returns the instance pointer (if found) and a boolean (true if found, false otherwise).
func (m *Master) FindInstance(id string) (*Instance, bool) {
	value, exists := m.Instances.Load(id)
	if !exists {
		return nil, false
	}
	return value.(*Instance), true
}

// StartInstance starts a nodepass instance as a subprocess, capturing its output and
// managing its lifecycle. It validates the instance state and initializes metric tracking.
//
// Checks that the instance is in "stopped" status before starting. Saves the current
// traffic counters as base values for delta calculations. Forks a child process running
// the nodepass binary with the instance URL as the argument. The child's stdout and
// stderr are attached to an InstanceLogWriter that parses metrics and forwards logs.
// A context.WithCancel is used to allow graceful termination. On startup success, the
// instance status is set to "running" and MonitorInstance is started in a goroutine.
// On failure, the status is set to "error". The instance is stored back in the registry
// and an SSE update event is sent to all subscribers.
//
// Parameters:
//   - instance: The instance to start (must be in stopped status)
func (m *Master) StartInstance(instance *Instance) {
	if value, exists := m.Instances.Load(instance.ID); exists {
		instance = value.(*Instance)
		if instance.Status != "stopped" {
			return
		}
	}

	instance.tcpRXBase = instance.TCPRX
	instance.tcpTXBase = instance.TCPTX
	instance.udpRXBase = instance.UDPRX
	instance.udpTXBase = instance.UDPTX

	execPath, err := os.Executable()
	if err != nil {
		m.Logger.Error("StartInstance: get path failed: %v [%v]", err, instance.ID)
		instance.Status = "error"
		m.Instances.Store(instance.ID, instance)
		m.SendSSEEvent("update", instance)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, execPath, instance.URL)
	instance.cancelFunc = cancel

	writer := NewInstanceLogWriter(instance.ID, instance, os.Stdout, m)
	cmd.Stdout, cmd.Stderr = writer, writer

	m.Logger.Info("Instance starting: %v [%v]", instance.URL, instance.ID)

	if err := cmd.Start(); err != nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		if err != nil {
			m.Logger.Error("StartInstance: instance error: %v [%v]", err, instance.ID)
		} else {
			m.Logger.Error("StartInstance: instance start failed [%v]", instance.ID)
		}
		instance.Status = "error"
		m.Instances.Store(instance.ID, instance)
		m.SendSSEEvent("update", instance)
		cancel()
		return
	}

	instance.cmd = cmd
	instance.Status = "running"
	go m.MonitorInstance(instance, cmd)

	m.Instances.Store(instance.ID, instance)

	m.SendSSEEvent("update", instance)
}

// MonitorInstance continuously monitors an instance process and updates its status.
// It listens for process exit, context cancellation, and periodic checkpoints to detect unresponsive states.
//
// Waits for the process to exit via cmd.Wait(). If the process exits normally or with
// error, the instance status is updated (to "stopped" on success or "error" on failure).
// If the instance.stopped channel is closed (by StopInstance), this function returns.
// Periodically checks if a CHECK_POINT event has been received; if not within 3 times
// the report interval, marks the instance as "error" (indicating unresponsiveness).
// Status changes are persisted via SendSSEEvent to notify subscribers.
//
// Parameters:
//   - instance: The instance to monitor
//   - cmd: The exec.Cmd for the child process
func (m *Master) MonitorInstance(instance *Instance, cmd *exec.Cmd) {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case <-instance.stopped:
			return
		case err := <-done:
			if value, exists := m.Instances.Load(instance.ID); exists {
				instance = value.(*Instance)
				if instance.Status == "running" {
					if err != nil {
						m.Logger.Error("MonitorInstance: instance error: %v [%v]", err, instance.ID)
						instance.Status = "error"
					} else {
						instance.Status = "stopped"
					}
					m.Instances.Store(instance.ID, instance)
					m.SendSSEEvent("update", instance)
				}
			}
			return
		case <-time.After(common.ReportInterval):
			if !instance.lastCheckPoint.IsZero() && time.Since(instance.lastCheckPoint) > 3*common.ReportInterval {
				instance.Status = "error"
				m.Instances.Store(instance.ID, instance)
				m.SendSSEEvent("update", instance)
			}
		}
	}
}

// StopInstance gracefully stops an instance process with force kill timeout.
// It checks the instance status, sends termination signals, waits for process exit,
// and updates the instance status accordingly.
//
// If already stopped, returns immediately. Closes the instance.stopped channel to signal
// MonitorInstance to return. Sends SIGTERM (or SIGINT on Windows) to the process and
// cancels the context to initiate graceful shutdown. Waits for the process to exit
// within GracefulTimeout (5s); if timeout expires, sends SIGKILL. Resets all metric
// counters (ping, pool, TCP/UDP connection counts) to 0. A new stopped channel is
// allocated for potential future restarts. The instance state is persisted and an
// SSE update event is sent to subscribers.
//
// Parameters:
//   - instance: The instance to stop
func (m *Master) StopInstance(instance *Instance) {
	if instance.Status == "stopped" {
		return
	}

	if instance.cmd == nil || instance.cmd.Process == nil {
		instance.Status = "stopped"
		m.Instances.Store(instance.ID, instance)
		m.SendSSEEvent("update", instance)
		return
	}

	select {
	case <-instance.stopped:
	default:
		close(instance.stopped)
	}

	process := instance.cmd.Process
	if runtime.GOOS == "windows" {
		process.Signal(os.Interrupt)
	} else {
		process.Signal(syscall.SIGTERM)
	}

	if instance.cancelFunc != nil {
		instance.cancelFunc()
	}

	done := make(chan struct{})
	go func() {
		process.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.Logger.Info("Instance stopped [%v]", instance.ID)
	case <-time.After(GracefulTimeout):
		process.Kill()
		<-done
		m.Logger.Warn("Instance force killed [%v]", instance.ID)
	}

	instance.Status = "stopped"
	instance.stopped = make(chan struct{})
	instance.cancelFunc = nil
	instance.Ping = 0
	instance.Pool = 0
	instance.TCPS = 0
	instance.UDPS = 0
	m.Instances.Store(instance.ID, instance)

	go m.SaveState()

	m.SendSSEEvent("update", instance)
}

// ProcessInstanceAction executes the specified action (start/stop/restart) on an instance.
// It validates the instance state and calls the corresponding method to perform the action.
//
// Routes actions to the appropriate handler methods in a non-blocking manner (using
// goroutines for stop/start/restart operations). Validates that the instance can
// perform the action (e.g., only starts if stopped, only stops if not stopped).
// The restart action is asynchronous: stops the instance, waits BaseDuration,
// then starts it again.
//
// Parameters:
//   - instance: The instance to control
//   - action: One of "start", "stop", or "restart"
func (m *Master) ProcessInstanceAction(instance *Instance, action string) {
	switch action {
	case "start":
		if instance.Status == "stopped" {
			go m.StartInstance(instance)
		}
	case "stop":
		if instance.Status != "stopped" {
			go m.StopInstance(instance)
		}
	case "restart":
		go func() {
			m.StopInstance(instance)
			time.Sleep(BaseDuration)
			m.StartInstance(instance)
		}()
	}
}

// ReGenerateAPIKey generates a new API key and notifies all SSE clients.
//
// Generates a new 32-character hexadecimal API key and updates the API key instance.
// Prints the new key to stdout for visibility. Persists the new key to the state file
// and gracefully shuts down all SSE connections, forcing clients to reconnect with
// the new key. This effectively invalidates all existing API keys, requiring clients
// to restart and authenticate with the new key.
//
// Parameters:
//   - instance: The API key instance (usually the special APIKeyID entry)
func (m *Master) ReGenerateAPIKey(instance *Instance) {
	instance.URL = GenerateAPIKey()
	m.Instances.Store(APIKeyID, instance)
	fmt.Printf("%s  \033[32mINFO\033[0m  API Key regenerated: %v\n", time.Now().Format("2006-01-02 15:04:05.000"), instance.URL)
	go m.SaveState()
	go m.ShutdownSSEConnections()
}

// EnhanceURL adds master configuration parameters to an instance URL.
// It parses the URL, updates query parameters based on master settings and instance type,
// and returns the enhanced URL string.
//
// If the master has LogLevel configured and the URL doesn't already specify "log",
// adds the master's log level to the query. For server instances with TLS enabled
// (tlsCode != "0"), adds the TLS mode. If TLS mode is "2" (custom certs), adds the
// certificate and key file paths if not already specified. This allows master-wide
// configuration to be injected into instance URLs while respecting explicit URL parameters.
// Server instances also receive the default pool backend if none is configured.
//
// Parameters:
//   - instanceURL: The instance URL to enhance (scheme://[user@]host:port/path?query)
//   - instanceType: The instance type ("server" or "client")
//
// Returns the enhanced URL string, or the original URL if parsing fails.
func (m *Master) EnhanceURL(instanceURL string, instanceType string) string {
	parsedURL, err := url.Parse(instanceURL)
	if err != nil {
		m.Logger.Error("EnhanceURL: invalid URL format: %v", err)
		return instanceURL
	}

	query := parsedURL.Query()

	if m.LogLevel != "" && query.Get("log") == "" {
		query.Set("log", m.LogLevel)
	}

	if instanceType == "server" && m.TLSCode != "0" {
		if query.Get("tls") == "" {
			query.Set("tls", m.TLSCode)
		}

		if m.TLSCode == "2" {
			if m.CrtPath != "" && query.Get("crt") == "" {
				query.Set("crt", m.CrtPath)
			}
			if m.KeyPath != "" && query.Get("key") == "" {
				query.Set("key", m.KeyPath)
			}
		}
	}
	if instanceType == "server" && query.Get("type") == "" {
		query.Set("type", common.DefaultPoolType)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// GenerateConfigURL generates a full configuration URL for an instance.
// It parses the URL, updates query parameters based on master settings and instance type,
// and returns the enhanced URL string.
//
// Similar to EnhanceURL, but also adds sensible default parameters for clients and servers
// if not already specified. For clients, includes DNS TTL, SNI, load balancing strategy,
// pool size, mode, source IP, read timeout, rate limit, connection slots, PROXY protocol,
// blocked protocols, and TCP/UDP enable/disable flags. Servers get DNS TTL, load balancing,
// max pool size, mode, pool backend, source IP, timeouts, rate limits, and protocol settings. Master-level
// TLS and log settings are also applied. This ensures every instance has a complete,
// runnable configuration derived from master defaults and explicit instance parameters.
//
// Parameters:
//   - instance: The instance to generate config for
//
// Returns the full configuration URL string.
func (m *Master) GenerateConfigURL(instance *Instance) string {
	parsedURL, err := url.Parse(instance.URL)
	if err != nil {
		m.Logger.Error("GenerateConfigURL: invalid URL format: %v", err)
		return instance.URL
	}

	query := parsedURL.Query()

	if m.LogLevel != "" && query.Get("log") == "" {
		query.Set("log", m.LogLevel)
	}

	if instance.Type == "server" && m.TLSCode != "0" {
		if query.Get("tls") == "" {
			query.Set("tls", m.TLSCode)
		}

		if m.TLSCode == "2" {
			if m.CrtPath != "" && query.Get("crt") == "" {
				query.Set("crt", m.CrtPath)
			}
			if m.KeyPath != "" && query.Get("key") == "" {
				query.Set("key", m.KeyPath)
			}
		}
	}

	switch instance.Type {
	case "client":
		if query.Get("dns") == "" {
			query.Set("dns", common.DefaultDNSTTL.String())
		}
		if query.Get("sni") == "" {
			query.Set("sni", common.DefaultServerName)
		}
		if query.Get("lbs") == "" {
			query.Set("lbs", common.DefaultLBStrategy)
		}
		if query.Get("min") == "" {
			query.Set("min", strconv.Itoa(common.DefaultMinPool))
		}
		if query.Get("mode") == "" {
			query.Set("mode", common.DefaultRunMode)
		}
		if query.Get("type") == "" {
			query.Set("type", common.DefaultPoolType)
		}
		if query.Get("dial") == "" {
			query.Set("dial", common.DefaultDialerIP)
		}
		if query.Get("read") == "" {
			query.Set("read", common.DefaultReadTimeout.String())
		}
		if query.Get("rate") == "" {
			query.Set("rate", strconv.Itoa(common.DefaultRateLimit))
		}
		if query.Get("slot") == "" {
			query.Set("slot", strconv.Itoa(common.DefaultSlotLimit))
		}
		if query.Get("proxy") == "" {
			query.Set("proxy", common.DefaultProxyProtocol)
		}
		if query.Get("block") == "" {
			query.Set("block", common.DefaultBlockProtocol)
		}
		if query.Get("notcp") == "" {
			query.Set("notcp", common.DefaultTCPStrategy)
		}
		if query.Get("noudp") == "" {
			query.Set("noudp", common.DefaultUDPStrategy)
		}
	case "server":
		if query.Get("dns") == "" {
			query.Set("dns", common.DefaultDNSTTL.String())
		}
		if query.Get("lbs") == "" {
			query.Set("lbs", common.DefaultLBStrategy)
		}
		if query.Get("max") == "" {
			query.Set("max", strconv.Itoa(common.DefaultMaxPool))
		}
		if query.Get("mode") == "" {
			query.Set("mode", common.DefaultRunMode)
		}
		if query.Get("dial") == "" {
			query.Set("dial", common.DefaultDialerIP)
		}
		if query.Get("read") == "" {
			query.Set("read", common.DefaultReadTimeout.String())
		}
		if query.Get("rate") == "" {
			query.Set("rate", strconv.Itoa(common.DefaultRateLimit))
		}
		if query.Get("slot") == "" {
			query.Set("slot", strconv.Itoa(common.DefaultSlotLimit))
		}
		if query.Get("proxy") == "" {
			query.Set("proxy", common.DefaultProxyProtocol)
		}
		if query.Get("block") == "" {
			query.Set("block", common.DefaultBlockProtocol)
		}
		if query.Get("notcp") == "" {
			query.Set("notcp", common.DefaultTCPStrategy)
		}
		if query.Get("noudp") == "" {
			query.Set("noudp", common.DefaultUDPStrategy)
		}
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// SetInstanceURL updates an instance's URL configuration with the provided parameters,
// stops the running instance if necessary, and restarts it with the new configuration.
//
// Parses the instance's current URL and applies updates to the URL components or query
// parameters. Supports updating "type" (scheme), "pool" (query type), "password" (auth), "tunnel_address",
// "tunnel_port", "target_address", "target_port", "targets" (path), and any query
// parameters. Query parameter values are replaced or deleted (if empty). Validates that
// the type is "client" or "server". Returns an error if no changes are detected.
// Stops the instance if running, replaces the URL, regenerates the config, and restarts.
// The new state is persisted asynchronously and an SSE update event is sent.
//
// Parameters:
//   - instance: The instance to update
//   - updates: Map of field names to new values
//
// Returns an error if the URL is invalid, type is invalid, or no changes detected.
func (m *Master) SetInstanceURL(instance *Instance, updates map[string]string) error {
	parsedURL, err := url.Parse(instance.URL)
	if err != nil {
		return fmt.Errorf("SetInstanceURL: invalid URL format: %w", err)
	}

	query := parsedURL.Query()

	for key, value := range updates {
		switch key {
		case "type":
			if value != "client" && value != "server" {
				return fmt.Errorf("SetInstanceURL: invalid type: must be 'client' or 'server'")
			}
			parsedURL.Scheme = value
			instance.Type = value
		case "pool":
			if value == "" {
				query.Del("type")
			} else {
				query.Set("type", value)
			}
		case "password":
			if value == "" {
				parsedURL.User = nil
			} else {
				parsedURL.User = url.User(value)
			}
		case "tunnel_address":
			parsedURL.Host = value + ":" + parsedURL.Port()
		case "tunnel_port":
			parsedURL.Host = parsedURL.Hostname() + ":" + value
		case "target_address", "target_port":
			pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), ":")
			if key == "target_address" {
				pathParts[0] = value
			} else if len(pathParts) > 1 {
				pathParts[1] = value
			} else {
				pathParts = append(pathParts, value)
			}
			parsedURL.Path = "/" + strings.Join(pathParts, ":")
		case "targets":
			parsedURL.Path = "/" + value
		default:
			if value == "" {
				query.Del(key)
			} else {
				query.Set(key, value)
			}
		}
	}

	parsedURL.RawQuery = query.Encode()
	newURL := parsedURL.String()

	if newURL == instance.URL {
		return fmt.Errorf("SetInstanceURL: no changes detected")
	}

	if instance.Status != "stopped" {
		m.StopInstance(instance)
		time.Sleep(BaseDuration)
	}

	instance.URL = newURL
	instance.Config = m.GenerateConfigURL(instance)
	instance.Status = "stopped"
	m.Instances.Store(instance.ID, instance)

	go m.StartInstance(instance)
	go func() {
		time.Sleep(BaseDuration)
		m.SaveState()
	}()

	return nil
}
