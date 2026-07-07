// rest.go implements the REST API handlers for the Master: CRUD operations on
// tunnel instances, system info, TCP latency probing, and the OpenAPI spec endpoint.
package master

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// HandleInstances handles REST API requests for listing and creating instances.
// GET returns all instances, POST creates a new instance.
//
// GET: Returns a JSON array of all instances (including the special API key instance).
// POST: Creates a new instance from a JSON request body containing "url" and optional "alias".
// The URL is parsed to extract the instance type (scheme). Invalid URLs or types result
// in 400 Bad Request. A unique ID is generated; conflicts are rejected with 409 Conflict.
// The instance is started asynchronously. Restart policy defaults to true (auto-restart).
// The instance registry and state file are updated. An SSE "create" event is sent.
//
// Request body format for POST:
//
//	{"url": "client://localhost:8080/target.com:443", "alias": "optional label"}
//
// Other HTTP methods receive 405 Method Not Allowed.
func (m *Master) HandleInstances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		instances := []*Instance{}
		m.Instances.Range(func(_, value any) bool {
			instances = append(instances, value.(*Instance))
			return true
		})
		WriteJSON(w, http.StatusOK, instances)

	case http.MethodPost:
		var reqData struct {
			Alias string `json:"alias"`
			URL   string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil || reqData.URL == "" {
			HTTPError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		parsedURL, err := url.Parse(reqData.URL)
		if err != nil {
			HTTPError(w, "Invalid URL format", http.StatusBadRequest)
			return
		}

		instanceType := parsedURL.Scheme
		if instanceType != "client" && instanceType != "server" {
			HTTPError(w, "Invalid URL scheme", http.StatusBadRequest)
			return
		}

		id := GenerateID()
		if _, exists := m.Instances.Load(id); exists {
			HTTPError(w, "Instance ID already exists", http.StatusConflict)
			return
		}

		instance := &Instance{
			ID:      id,
			Alias:   reqData.Alias,
			Type:    instanceType,
			URL:     m.EnhanceURL(reqData.URL, instanceType),
			Status:  "stopped",
			Restart: true,
			Meta:    Meta{Tags: make(map[string]string)},
			stopped: make(chan struct{}),
		}

		instance.Config = m.GenerateConfigURL(instance)
		m.Instances.Store(id, instance)

		go m.StartInstance(instance)

		go func() {
			time.Sleep(BaseDuration)
			m.SaveState()
		}()
		WriteJSON(w, http.StatusCreated, instance)

		m.SendSSEEvent("create", instance)

	default:
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleInstanceDetail dispatches REST API requests for individual instance operations.
// Supports GET (retrieve), PATCH (update), PUT (replace URL), and DELETE (remove) operations.
//
// Extracts the instance ID from the URL path. Returns 400 if missing, 404 if not found.
// Routes to the appropriate handler based on HTTP method:
//   - GET: Returns the instance details
//   - PATCH: Updates alias, actions, restart policy, and metadata
//   - PUT: Replaces the entire URL configuration
//   - DELETE: Removes the instance
//
// Other HTTP methods receive 405 Method Not Allowed.
func (m *Master) HandleInstanceDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("%s/instances/", m.Prefix))
	if id == "" || id == "/" {
		HTTPError(w, "Instance ID is required", http.StatusBadRequest)
		return
	}

	instance, ok := m.FindInstance(id)
	if !ok {
		HTTPError(w, "Instance not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		m.HandleGetInstance(w, instance)
	case http.MethodPatch:
		m.HandlePatchInstance(w, r, id, instance)
	case http.MethodPut:
		m.HandlePutInstance(w, r, id, instance)
	case http.MethodDelete:
		m.HandleDeleteInstance(w, id, instance)
	default:
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleGetInstance retrieves and returns the details of a specific instance.
//
// Returns the instance as a JSON object with all current state (status, metrics, config).
// Status 200 on success.
func (m *Master) HandleGetInstance(w http.ResponseWriter, instance *Instance) {
	WriteJSON(w, http.StatusOK, instance)
}

// HandlePatchInstance partially updates instance configuration including alias, actions, restart policy, and metadata.
//
// For the API key instance (APIKeyID), only the "restart" action (regenerate key) is allowed.
// For regular instances, supports:
//   - "alias": Updates the human-readable name (max 256 chars)
//   - "action": Executes one of {start, stop, restart, reset}
//   - reset: Clears traffic counters and base values
//   - "restart": Sets the auto-restart flag (boolean)
//   - "meta": Updates peer linkage (SID, type, alias) and tags (key-value pairs)
//   - Peer fields and tag keys/values are validated (max 256 chars each)
//   - Detects duplicate tag keys and rejects with 400
//
// Changes trigger state persistence and SSE "update" events.
// Request body is JSON with optional fields; invalid JSON is silently ignored.
func (m *Master) HandlePatchInstance(w http.ResponseWriter, r *http.Request, id string, instance *Instance) {
	var reqData struct {
		Alias   string `json:"alias,omitempty"`
		Action  string `json:"action,omitempty"`
		Restart *bool  `json:"restart,omitempty"`
		Meta    *struct {
			Peer *Peer             `json:"peer,omitempty"`
			Tags map[string]string `json:"tags,omitempty"`
		} `json:"meta,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err == nil {
		if id == APIKeyID {
			if reqData.Action == "restart" {
				m.ReGenerateAPIKey(instance)
				m.SendSSEEvent("update", instance)
			}
		} else {
			if reqData.Alias != "" && instance.Alias != reqData.Alias {
				if len(reqData.Alias) > MaxValueLen {
					HTTPError(w, fmt.Sprintf("Instance alias exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
					return
				}
				instance.Alias = reqData.Alias
				m.Instances.Store(id, instance)
				go m.SaveState()
				m.Logger.Info("Alias updated: %v [%v]", reqData.Alias, instance.ID)

				m.SendSSEEvent("update", instance)
			}

			if reqData.Action != "" {
				validActions := map[string]bool{
					"start":   true,
					"stop":    true,
					"restart": true,
					"reset":   true,
				}
				if !validActions[reqData.Action] {
					HTTPError(w, fmt.Sprintf("Invalid action: %s", reqData.Action), http.StatusBadRequest)
					return
				}

				if reqData.Action == "reset" {
					instance.tcpRXReset = instance.TCPRX - instance.tcpRXBase
					instance.tcpTXReset = instance.TCPTX - instance.tcpTXBase
					instance.udpRXReset = instance.UDPRX - instance.udpRXBase
					instance.udpTXReset = instance.UDPTX - instance.udpTXBase
					instance.TCPRX = 0
					instance.TCPTX = 0
					instance.UDPRX = 0
					instance.UDPTX = 0
					instance.tcpRXBase = 0
					instance.tcpTXBase = 0
					instance.udpRXBase = 0
					instance.udpTXBase = 0
					m.Instances.Store(id, instance)
					go m.SaveState()
					m.Logger.Info("Traffic stats reset: 0 [%v]", instance.ID)

					m.SendSSEEvent("update", instance)
				} else {
					m.ProcessInstanceAction(instance, reqData.Action)
				}
			}

			if reqData.Restart != nil && instance.Restart != *reqData.Restart {
				instance.Restart = *reqData.Restart
				m.Instances.Store(id, instance)
				go m.SaveState()
				m.Logger.Info("Restart policy updated: %v [%v]", *reqData.Restart, instance.ID)

				m.SendSSEEvent("update", instance)
			}

			if reqData.Meta != nil {
				if reqData.Meta.Peer != nil {
					if len(reqData.Meta.Peer.SID) > MaxValueLen {
						HTTPError(w, fmt.Sprintf("Meta peer.sid exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
						return
					}
					if len(reqData.Meta.Peer.Type) > MaxValueLen {
						HTTPError(w, fmt.Sprintf("Meta peer.type exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
						return
					}
					if len(reqData.Meta.Peer.Alias) > MaxValueLen {
						HTTPError(w, fmt.Sprintf("Meta peer.alias exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
						return
					}
					instance.Meta.Peer = *reqData.Meta.Peer
				}

				if reqData.Meta.Tags != nil {
					seen := make(map[string]bool)
					for key, value := range reqData.Meta.Tags {
						if len(key) > MaxValueLen {
							HTTPError(w, fmt.Sprintf("Meta tag key exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
							return
						}
						if len(value) > MaxValueLen {
							HTTPError(w, fmt.Sprintf("Meta tag value exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
							return
						}
						if seen[key] {
							HTTPError(w, fmt.Sprintf("Duplicate meta tag key: %s", key), http.StatusBadRequest)
							return
						}
						seen[key] = true
					}
					instance.Meta.Tags = reqData.Meta.Tags
				}

				m.Instances.Store(id, instance)
				go m.SaveState()
				m.Logger.Info("Meta updated [%v]", instance.ID)
				m.SendSSEEvent("update", instance)
			}

		}
	}
	WriteJSON(w, http.StatusOK, instance)
}

// HandlePutInstance replaces the instance URL configuration and restarts the instance with new settings.
//
// Forbidden for the API key instance (403 Forbidden). Expects JSON with a "url" field.
// The URL must have a valid scheme (client or server); otherwise, returns 400.
// If the enhanced URL matches the existing URL, returns 409 Conflict. Stops the instance
// if running, replaces the URL, regenerates the config, and restarts it.
// The new configuration is persisted and an SSE "update" event is sent.
//
// Request body format:
//
//	{"url": "server://0.0.0.0:8080/target.com:443"}
func (m *Master) HandlePutInstance(w http.ResponseWriter, r *http.Request, id string, instance *Instance) {
	if id == APIKeyID {
		HTTPError(w, "Forbidden: API Key", http.StatusForbidden)
		return
	}

	var reqData struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil || reqData.URL == "" {
		HTTPError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	parsedURL, err := url.Parse(reqData.URL)
	if err != nil {
		HTTPError(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	instanceType := parsedURL.Scheme
	if instanceType != "client" && instanceType != "server" {
		HTTPError(w, "Invalid URL scheme", http.StatusBadRequest)
		return
	}

	enhancedURL := m.EnhanceURL(reqData.URL, instanceType)

	if instance.URL == enhancedURL {
		HTTPError(w, "Instance URL conflict", http.StatusConflict)
		return
	}

	if instance.Status != "stopped" {
		m.StopInstance(instance)
		time.Sleep(BaseDuration)
	}

	instance.URL = enhancedURL
	instance.Type = instanceType
	instance.Config = m.GenerateConfigURL(instance)

	instance.Status = "stopped"
	m.Instances.Store(id, instance)

	go m.StartInstance(instance)

	go func() {
		time.Sleep(BaseDuration)
		m.SaveState()
	}()
	WriteJSON(w, http.StatusOK, instance)

	m.Logger.Info("Instance URL updated: %v [%v]", instance.URL, instance.ID)
}

// HandleDeleteInstance removes an instance from the master, stops it if running, and notifies subscribers.
//
// Forbidden for the API key instance (403 Forbidden). Marks the instance as deleted,
// stops it if running (this suppresses further log events), removes it from the registry,
// and persists the new state. Responds with 204 No Content. An SSE "delete" event is sent
// to notify subscribers of the removal.
func (m *Master) HandleDeleteInstance(w http.ResponseWriter, id string, instance *Instance) {
	if id == APIKeyID {
		HTTPError(w, "Forbidden: API Key", http.StatusForbidden)
		return
	}

	instance.deleted = true
	m.Instances.Store(id, instance)

	if instance.Status != "stopped" {
		m.StopInstance(instance)
	}
	m.Instances.Delete(id)
	go m.SaveState()
	w.WriteHeader(http.StatusNoContent)
	m.SendSSEEvent("delete", instance)
}

// HandleInfo handles REST API requests for retrieving and updating master information and alias.
//
// GET: Returns master information from GetMasterInfo() including system stats, version, uptime,
// TLS configuration, and the master's alias/name.
// POST: Updates the master's alias from a JSON request {"alias": "new name"}. The alias is
// stored in the API key instance as well for persistence. Max length is 256 chars. Returns
// updated master info on success.
//
// Other HTTP methods receive 405 Method Not Allowed.
func (m *Master) HandleInfo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		WriteJSON(w, http.StatusOK, m.GetMasterInfo())

	case http.MethodPost:
		var reqData struct {
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
			HTTPError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(reqData.Alias) > MaxValueLen {
			HTTPError(w, fmt.Sprintf("Master alias exceeds maximum length %d", MaxValueLen), http.StatusBadRequest)
			return
		}
		m.Alias = reqData.Alias

		if apiKey, ok := m.FindInstance(APIKeyID); ok {
			apiKey.Alias = m.Alias
			m.Instances.Store(APIKeyID, apiKey)
			go m.SaveState()
		}

		WriteJSON(w, http.StatusOK, m.GetMasterInfo())

	default:
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleTCPing handles REST API requests for TCP connectivity testing to a target address.
//
// Only accepts GET requests; other methods return 405. Requires a "target" query parameter
// (host:port format); returns 400 if missing. Delegates to PerformTCPing for the actual
// test and returns the result as JSON (includes success status and latency in milliseconds).
func (m *Master) HandleTCPing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		HTTPError(w, "Target address required", http.StatusBadRequest)
		return
	}

	result := m.PerformTCPing(target)
	WriteJSON(w, http.StatusOK, result)
}

// PerformTCPing performs a TCP connection test to a target address and returns connectivity and latency information.
//
// Acquires a semaphore (max PingSemLimit concurrent pings) with a 1-second timeout.
// Returns "too many requests" error if the semaphore is full. Measures the time to
// establish a TCP connection to the target with a timeout of ReportInterval. Records
// whether the connection succeeded, the latency in milliseconds, and any error message.
// Useful for verifying network connectivity to remote endpoints.
//
// Parameters:
//   - target: Target address in "host:port" format
//
// Returns a TCPingResult containing success status, latency (ms), and optional error.
func (m *Master) PerformTCPing(target string) *TCPingResult {
	result := &TCPingResult{
		Target:    target,
		Connected: false,
		Latency:   0,
		Error:     nil,
	}

	select {
	case m.TCPingSem <- struct{}{}:
		defer func() { <-m.TCPingSem }()
	case <-time.After(time.Second):
		errMsg := "too many requests"
		result.Error = &errMsg
		return result
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, common.ReportInterval)
	if err != nil {
		errMsg := err.Error()
		result.Error = &errMsg
		return result
	}

	result.Connected = true
	result.Latency = time.Since(start).Milliseconds()
	conn.Close()
	return result
}

// HandleOpenAPISpec serves the OpenAPI specification for the master's REST API.
//
// Returns the OpenAPI 3.1.1 specification as JSON (generated by GenerateOpenAPISpec).
// This is a public endpoint (no API key required) that documents all REST API operations.
// Clients can use this spec to auto-generate SDK code or for API documentation.
func (m *Master) HandleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	SetCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(m.GenerateOpenAPISpec()))
}

// HandleSwaggerUI serves the Swagger UI interface for exploring the master's REST API.
//
// Returns an HTML page embedding the Swagger UI (from CDN) with the OpenAPI spec injected.
// This is a public endpoint that allows users to interactively test API endpoints through
// a web browser. The Swagger UI allows sending test requests and viewing responses.
func (m *Master) HandleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	SetCorsHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, SwaggerUIHTML, m.GenerateOpenAPISpec())
}
