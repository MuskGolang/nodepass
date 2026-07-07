// control.go contains the control-channel management for pooled tunnel mode.
// The control connection is a dedicated logical channel multiplexed over the
// first connection taken from the tunnel pool. It carries JSON-encoded Signal
// messages (XOR-obfuscated and base64-encoded) that coordinate TCP/UDP flow
// start, health pings, TLS verification, and pool flush requests.
package common

import (
	"bufio"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NodePassProject/nodepass/internal/transport"
)

// SetControlConn waits for the tunnel pool to become ready, then claims the special control connection
// (ID "00000000") from the pool. Starts a background writer goroutine that drains WriteChan onto the wire
// in real-time, and sets up a buffered reader for efficient inbound signal reception.
// Returns an error on HandshakeTimeout or if the pool connection cannot be obtained.
func (c *Common) SetControlConn() error {
	start := time.Now()
	for c.Ctx.Err() == nil {
		if c.TunnelPool.Ready() && c.TunnelPool.Active() > 0 {
			break
		}
		if time.Since(start) > HandshakeTimeout {
			return fmt.Errorf("SetControlConn: handshake timeout")
		}
		select {
		case <-c.Ctx.Done():
			return fmt.Errorf("SetControlConn: context error: %w", c.Ctx.Err())
		case <-time.After(ContextCheckInterval):
		}
	}

	poolConn, err := c.TunnelPool.OutgoingGet("00000000", PoolGetTimeout)
	if err != nil {
		return fmt.Errorf("SetControlConn: outgoingGet failed: %w", err)
	}
	c.ControlConn = poolConn
	c.BufReader = bufio.NewReader(transport.NewTimeoutReader(c.ControlConn, 3*ReportInterval))
	c.Logger.Info("Marking tunnel handshake as complete in %vms", time.Since(c.HandshakeStart).Milliseconds())

	go func() {
		for {
			select {
			case <-c.Ctx.Done():
				return
			case data := <-c.WriteChan:
				_, err := c.ControlConn.Write(data)
				if err != nil {
					c.Logger.Error("SetControlConn: write failed: %v", err)
				}
			}
		}
	}()

	if c.TLSCode == "1" {
		c.Logger.Info("TLS code-1: RAM cert fingerprint verifying...")
	}
	return nil
}

// TunnelControl orchestrates pooled-mode control plane by launching three concurrent goroutines:
// 1. TunnelOnce: signal dispatcher (handles individual TCP/UDP transfers)
// 2. TunnelQueue: inbound signal reader (receives and queues signals from peer)
// 3. HealthCheck: health monitoring (ping/pong, pool flush, latency probing)
// Returns the first error any goroutine produces, or context cancellation error.
func (c *Common) TunnelControl() error {
	errChan := make(chan error, 3)

	go func() { errChan <- c.TunnelOnce() }()
	go func() { errChan <- c.TunnelQueue() }()
	go func() { errChan <- c.HealthCheck() }()

	select {
	case <-c.Ctx.Done():
		return fmt.Errorf("TunnelControl: context error: %w", c.Ctx.Err())
	case err := <-errChan:
		return fmt.Errorf("TunnelControl: %w", err)
	}
}

// TunnelQueue reads newline-delimited encoded signals from the buffered control-connection reader,
// decodes each one, and dispatches it to SignalChan for processing by TunnelOnce.
// Returns an error when the connection breaks, decoding fails persistently, the queue is full,
// or the context is cancelled.
func (c *Common) TunnelQueue() error {
	for c.Ctx.Err() == nil {
		rawSignal, err := c.BufReader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("TunnelQueue: readBytes failed: %w", err)
		}

		signalData, err := c.Decode(rawSignal)
		if err != nil {
			c.Logger.Error("TunnelQueue: decode signal failed: %v", err)
			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("TunnelQueue: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		var signal Signal
		if err := json.Unmarshal(signalData, &signal); err != nil {
			c.Logger.Error("TunnelQueue: unmarshal signal failed: %v", err)
			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("TunnelQueue: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		select {
		case c.SignalChan <- signal:
		default:
			c.Logger.Error("TunnelQueue: queue limit reached: %v", SemaphoreLimit)
			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("TunnelQueue: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
		}
	}

	return fmt.Errorf("TunnelQueue: context error: %w", c.Ctx.Err())
}

// HealthCheck monitors tunnel health on a ReportInterval ticker. Performs the following:
// 1. Initiates TLS code-1 verification if enabled (sends IncomingVerify after initial delay)
// 2. Monitors pool error rate and triggers flush when ErrorCount > Active()/2
// 3. Probes best latency target when LBStrategy "1" is active (latency-based load-balancing)
// 4. Sends periodic ping signals and measures round-trip latency (logged in CHECK_POINT events)
func (c *Common) HealthCheck() error {
	ticker := time.NewTicker(ReportInterval)
	defer ticker.Stop()

	if c.TLSCode == "1" {
		go func() {
			select {
			case <-c.Ctx.Done():
			case <-time.After(ReportInterval):
				c.IncomingVerify()
			}
		}()
	}

	for c.Ctx.Err() == nil {
		if c.TunnelPool.ErrorCount() > c.TunnelPool.Active()/2 {
			if c.Ctx.Err() == nil && c.ControlConn != nil {
				signalData, _ := json.Marshal(Signal{ActionType: "flush"})
				c.WriteChan <- c.Encode(signalData)
			}
			c.TunnelPool.Flush()
			c.TunnelPool.ResetError()

			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("HealthCheck: context error: %w", c.Ctx.Err())
			case <-ticker.C:
			}

			c.Logger.Debug("Tunnel pool flushed: %v active connections", c.TunnelPool.Active())
		}

		if c.LBStrategy == "1" && len(c.TargetTCPAddrs) > 1 {
			c.ProbeBestTarget()
		}

		c.CheckPoint = time.Now()
		if c.Ctx.Err() == nil && c.ControlConn != nil {
			signalData, _ := json.Marshal(Signal{ActionType: "ping"})
			c.WriteChan <- c.Encode(signalData)
		}
		select {
		case <-c.Ctx.Done():
			return fmt.Errorf("HealthCheck: context error: %w", c.Ctx.Err())
		case <-ticker.C:
		}
	}

	return fmt.Errorf("HealthCheck: context error: %w", c.Ctx.Err())
}

// SingleControl orchestrates single-connection mode control plane by launching data loops concurrently:
// 1. SingleEventLoop: emits periodic CHECK_POINT metric events (if targets exist)
// 2. SingleTCPLoop: accepts TCP connections and dials targets (if TCP enabled)
// 3. SingleUDPLoop: handles UDP datagrams and sessions (if UDP enabled)
// Returns the first error any goroutine produces, or context cancellation error.
func (c *Common) SingleControl() error {
	errChan := make(chan error, 3)

	if len(c.TargetTCPAddrs) > 0 {
		go func() { errChan <- c.SingleEventLoop() }()
	}
	if c.TunnelListener != nil || c.DisableTCP != "1" {
		go func() { errChan <- c.SingleTCPLoop() }()
	}
	if c.TunnelUDPConn != nil || c.DisableUDP != "1" {
		go func() { errChan <- c.SingleUDPLoop() }()
	}

	select {
	case <-c.Ctx.Done():
		return fmt.Errorf("SingleControl: context error: %w", c.Ctx.Err())
	case err := <-errChan:
		return fmt.Errorf("SingleControl: %w", err)
	}
}
