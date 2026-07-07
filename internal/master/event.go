// event.go implements Server-Sent Events (SSE) streaming for real-time instance
// log and status updates, and manages the event dispatcher goroutine.
package master

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NewInstanceLogWriter creates a new InstanceLogWriter that parses instance output logs
// and extracts metrics and status information for real-time monitoring.
//
// The log writer processes child process output, looking for CHECK_POINT events
// containing instance metrics (mode, ping, pool size, connection stats). These
// metrics are extracted via regex and updated in the instance state. All output
// is simultaneously written to the target (usually stdout for logging purposes).
// The instance status is automatically updated from error to running when a
// CHECK_POINT is received.
//
// Parameters:
//   - instanceID: Unique identifier for the instance (for logging)
//   - instance: Pointer to the Instance being monitored
//   - target: io.Writer to receive all output (stdout, file, etc.)
//   - master: Reference to the Master for sending SSE events and accessing the instance registry
//
// Returns a new InstanceLogWriter configured with the CHECK_POINT regex pattern.
func NewInstanceLogWriter(instanceID string, instance *Instance, target io.Writer, master *Master) *InstanceLogWriter {
	return &InstanceLogWriter{
		InstanceID: instanceID,
		Instance:   instance,
		Target:     target,
		Master:     master,
		CheckPoint: regexp.MustCompile(`CHECK_POINT\|MODE=(\d+)\|PING=(\d+)ms\|POOL=(\d+)\|TCPS=(\d+)\|UDPS=(\d+)\|TCPRX=(\d+)\|TCPTX=(\d+)\|UDPRX=(\d+)\|UDPTX=(\d+)`),
	}
}

// Write processes instance log output, extracting metrics from CHECK_POINT events
// and forwarding logs to the target writer.
//
// Scans incoming log lines for CHECK_POINT events containing metrics like mode,
// ping latency, connection pool size, and traffic statistics. When a CHECK_POINT
// is found, the instance fields are updated with parsed values. Traffic counters
// account for resets by subtracting base and reset values. The instance status
// is automatically updated to "running" if it was in "error" state. Lines
// containing "Server error:" or "Client error:" mark the instance as errored.
// Non-CHECK_POINT lines are logged with the instance ID appended. All events
// trigger SSE broadcasts to subscribers.
//
// Parameters:
//   - p: Byte slice containing the log data to process
//
// Returns the number of bytes processed (always len(p)) and any scanning errors.
func (w *InstanceLogWriter) Write(p []byte) (n int, err error) {
	s := string(p)
	scanner := bufio.NewScanner(strings.NewReader(s))

	for scanner.Scan() {
		line := scanner.Text()
		if matches := w.CheckPoint.FindStringSubmatch(line); len(matches) == 10 {
			if mode, err := strconv.ParseInt(matches[1], 10, 32); err == nil {
				w.Instance.Mode = int32(mode)
			}
			if ping, err := strconv.ParseInt(matches[2], 10, 32); err == nil {
				w.Instance.Ping = int32(ping)
			}
			if pool, err := strconv.ParseInt(matches[3], 10, 32); err == nil {
				w.Instance.Pool = int32(pool)
			}
			if tcps, err := strconv.ParseInt(matches[4], 10, 32); err == nil {
				w.Instance.TCPS = int32(tcps)
			}
			if udps, err := strconv.ParseInt(matches[5], 10, 32); err == nil {
				w.Instance.UDPS = int32(udps)
			}

			stats := []*uint64{&w.Instance.TCPRX, &w.Instance.TCPTX, &w.Instance.UDPRX, &w.Instance.UDPTX}
			bases := []uint64{w.Instance.tcpRXBase, w.Instance.tcpTXBase, w.Instance.udpRXBase, w.Instance.udpTXBase}
			resets := []*uint64{&w.Instance.tcpRXReset, &w.Instance.tcpTXReset, &w.Instance.udpRXReset, &w.Instance.udpTXReset}
			for i, stat := range stats {
				if v, err := strconv.ParseUint(matches[i+6], 10, 64); err == nil {
					if v >= *resets[i] {
						*stat = bases[i] + v - *resets[i]
					} else {
						*stat = bases[i] + v
						*resets[i] = 0
					}
				}
			}

			w.Instance.lastCheckPoint = time.Now()

			if w.Instance.Status == "error" {
				w.Instance.Status = "running"
			}

			if !w.Instance.deleted {
				w.Master.Instances.Store(w.InstanceID, w.Instance)
				w.Master.SendSSEEvent("update", w.Instance)
			}
			continue
		}

		if w.Instance.Status != "error" && !w.Instance.deleted &&
			(strings.Contains(line, "Server error:") || strings.Contains(line, "Client error:")) {
			w.Instance.Status = "error"
			w.Instance.Ping = 0
			w.Instance.Pool = 0
			w.Instance.TCPS = 0
			w.Instance.UDPS = 0
			w.Master.Instances.Store(w.InstanceID, w.Instance)
		}

		fmt.Fprintf(w.Target, "%s [%s]\n", line, w.InstanceID)

		if !w.Instance.deleted {
			w.Master.SendSSEEvent("log", w.Instance, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(w.Target, "%s [%s]", s, w.InstanceID)
	}
	return len(p), nil
}

// HandleSSE handles Server-Sent Events connections for real-time instance updates.
// It registers the client as a subscriber and sends initial state followed by continuous updates.
//
// Sets up SSE headers (text/event-stream, no-cache) and generates a unique subscriber ID.
// Creates a buffered event channel that is registered in the Subscribers map. Sends
// a retry hint (SSERetryTime ms) and all current instance states as "initial" events.
// Then enters a loop listening for new events from the channel or context cancellation.
// When the client disconnects or the context is cancelled, the channel is cleaned up.
// All events are marshalled to JSON and formatted as SSE messages (event: instance).
//
// Only accepts GET requests; other methods receive a 405 Method Not Allowed response.
// On connection loss, the goroutine that monitors the context notifies the channel close.
func (m *Master) HandleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		HTTPError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	subscriberID := GenerateID()

	events := make(chan *InstanceEvent, 10)

	m.Subscribers.Store(subscriberID, events)
	defer m.Subscribers.Delete(subscriberID)

	fmt.Fprintf(w, "retry: %d\n\n", SSERetryTime)

	m.Instances.Range(func(_, value any) bool {
		instance := value.(*Instance)
		event := &InstanceEvent{
			Type:     "initial",
			Time:     time.Now(),
			Instance: instance,
		}

		data, err := json.Marshal(event)
		if err == nil {
			fmt.Fprintf(w, "event: instance\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
		}
		return true
	})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	connectionClosed := make(chan struct{})

	go func() {
		<-ctx.Done()
		close(connectionClosed)
		if ch, exists := m.Subscribers.LoadAndDelete(subscriberID); exists {
			close(ch.(chan *InstanceEvent))
		}
	}()

	for {
		select {
		case <-connectionClosed:
			return
		case event, ok := <-events:
			if !ok {
				return
			}

			data, err := json.Marshal(event)
			if err != nil {
				m.Logger.Error("HandleSSE: event marshal error: %v", err)
				continue
			}

			fmt.Fprintf(w, "event: instance\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
		}
	}
}

// SendSSEEvent sends an event to the notification channel for broadcasting to all SSE subscribers.
// It includes the event type, instance state, and optional log messages.
//
// Constructs an InstanceEvent with the given type and timestamp. If a log message
// is provided, it is included in the event (only the first log message is used).
// The event is sent to the NotifyChannel in a non-blocking manner (drops events
// if the channel buffer is full). This allows the event dispatcher to fan-out the
// event to all connected SSE subscribers. Common event types are "create", "update",
// "delete", "log", "initial", and "shutdown".
//
// Parameters:
//   - eventType: Type of event (e.g., "create", "update", "delete", "log")
//   - instance: The instance associated with the event
//   - logs: Optional log message(s); only the first is used
func (m *Master) SendSSEEvent(eventType string, instance *Instance, logs ...string) {
	event := &InstanceEvent{
		Type:     eventType,
		Time:     time.Now(),
		Instance: instance,
	}

	if len(logs) > 0 {
		event.Logs = logs[0]
	}

	select {
	case m.NotifyChannel <- event:
	default:
	}
}

// ShutdownSSEConnections gracefully closes all active SSE subscriber connections
// and notifies them of the master shutdown event.
//
// Iterates over all registered SSE subscribers and sends a "shutdown" event to each
// in parallel (using WaitGroup). Each subscriber receives a final event before its
// channel is closed. Attempts to send are non-blocking; if the channel buffer is full,
// the shutdown notification is silently dropped. This ensures that even unresponsive
// clients don't block the master shutdown process. The function waits for all
// notifications to complete before returning.
func (m *Master) ShutdownSSEConnections() {
	var wg sync.WaitGroup

	m.Subscribers.Range(func(key, value any) bool {
		ch := value.(chan *InstanceEvent)
		wg.Add(1)
		go func(subscriberID any, eventChan chan *InstanceEvent) {
			defer wg.Done()
			select {
			case eventChan <- &InstanceEvent{Type: "shutdown", Time: time.Now()}:
			default:
			}
			if _, exists := m.Subscribers.LoadAndDelete(subscriberID); exists {
				close(eventChan)
			}
		}(key, ch)
		return true
	})

	wg.Wait()
}

// StartEventDispatcher starts the event dispatcher goroutine that broadcasts instance events
// from the notification channel to all active SSE subscribers.
//
// Runs indefinitely (until NotifyChannel is closed), receiving events from the
// notification channel and fanning them out to all subscribers. Each event is
// sent to every subscriber's event channel using a non-blocking select (drops
// events if a subscriber's channel is full, indicating a slow client). This
// pattern decouples event senders from receivers and ensures fast event producers
// are not blocked by slow subscribers. The dispatcher should be started as a
// goroutine during master initialization.
func (m *Master) StartEventDispatcher() {
	for event := range m.NotifyChannel {
		m.Subscribers.Range(func(_, value any) bool {
			eventChan := value.(chan *InstanceEvent)
			select {
			case eventChan <- event:
			default:
			}
			return true
		})
	}
}
