// runtime.go provides lifecycle helpers for initialising and tearing down a
// Common instance: rate limiter, context, listeners, and graceful shutdown.
package common

import (
	"context"
	"fmt"
	"net"

	"github.com/NodePassProject/nodepass/internal/transport"
)

// InitRateLimiter creates a token-bucket RateLimiter if RateLimit > 0, limiting bandwidth.
// Both the fill rate (tokens added per second) and burst capacity equal RateLimit (in bytes/s).
// When RateLimit == 0, the limiter is nil and throughput is unlimited.
// Must be called after Config is populated and before any data transfer begins.
func (c *Common) InitRateLimiter() {
	if c.RateLimit > 0 {
		c.RateLimiter = transport.NewRateLimiter(int64(c.RateLimit), int64(c.RateLimit))
	}
}

// InitContext cancels any previous cancellation function (from a prior run) and creates a fresh
// cancellable context. Must be called at the start of each Start() invocation so that
// per-run goroutines see a clean cancellation signal and previous goroutines can exit.
// Uses context.Background() as the base context (no parent timeout).
func (c *Common) InitContext() {
	if c.Cancel != nil {
		c.Cancel() // cancel previous context if it exists
	}
	c.Ctx, c.Cancel = context.WithCancel(context.Background())
}

// InitTunnelListener opens the TCP and/or UDP listeners bound to the tunnel address.
// In client mode, these listeners accept inbound connections from clients and forward them over the tunnel.
// In server mode, these listeners are used differently (via TargetListener instead).
// TCP listener is opened unless DisableTCP == "1" or CoreType is "client" and NOT "server".
// UDP listener is opened unless DisableUDP == "1" or CoreType is "client" and NOT "server".
// TLS wrapping (if configured) is applied by the caller after this function returns.
// Returns error if any listener fails to open (address in use, permission denied, etc.).
func (c *Common) InitTunnelListener() error {
	if c.TunnelTCPAddr == nil && c.TunnelUDPAddr == nil {
		return fmt.Errorf("InitTunnelListener: nil tunnel address")
	}

	if c.TunnelTCPAddr != nil && (c.DisableTCP != "1" || c.CoreType != "client") {
		tunnelListener, err := net.ListenTCP("tcp", c.TunnelTCPAddr)
		if err != nil {
			return fmt.Errorf("InitTunnelListener: listenTCP failed: %w", err)
		}
		c.TunnelListener = tunnelListener
	}

	if c.TunnelUDPAddr != nil && (c.DisableUDP != "1" || c.CoreType != "client") {
		tunnelUDPConn, err := net.ListenUDP("udp", c.TunnelUDPAddr)
		if err != nil {
			return fmt.Errorf("InitTunnelListener: listenUDP failed: %w", err)
		}
		c.TunnelUDPConn = transport.NewStatConn(tunnelUDPConn, &c.UDPRX, &c.UDPTX, c.RateLimiter)
	}

	return nil
}

// InitTargetListener opens the TCP and/or UDP listeners bound to the first target address.
// Used when the local side accepts traffic destined for the remote target (DataFlow "-").
// TCP listener is opened when DisableTCP != "1" and at least one TCP target address exists.
// UDP listener is opened when DisableUDP != "1" and at least one UDP target address exists.
// Both listeners are wrapped with statistics tracking (StatConn) for traffic counting and rate limiting.
// Returns error if any listener fails to open or if no target addresses are available.
func (c *Common) InitTargetListener() error {
	if len(c.TargetAddrs) == 0 {
		return fmt.Errorf("InitTargetListener: no target address")
	}

	if len(c.TargetTCPAddrs) > 0 && c.DisableTCP != "1" {
		targetListener, err := net.ListenTCP("tcp", c.TargetTCPAddrs[0])
		if err != nil {
			return fmt.Errorf("InitTargetListener: listenTCP failed: %w", err)
		}
		c.TargetListener = targetListener
	}

	if len(c.TargetUDPAddrs) > 0 && c.DisableUDP != "1" {
		targetUDPConn, err := net.ListenUDP("udp", c.TargetUDPAddrs[0])
		if err != nil {
			return fmt.Errorf("InitTargetListener: listenUDP failed: %w", err)
		}
		c.TargetUDPConn = transport.NewStatConn(targetUDPConn, &c.UDPRX, &c.UDPTX, c.RateLimiter)
	}

	return nil
}

// Stop performs graceful shutdown of the tunnel instance by:
// 1. Cancelling the context (signals all goroutines to exit)
// 2. Closing the tunnel pool (all pre-established connections)
// 3. Closing all UDP sessions (target-side)
// 4. Closing all listeners (tunnel and target, TCP and UDP)
// 5. Closing the control connection
// 6. Draining buffered channels (SignalChan, WriteChan, VerifyChan) to release blocked goroutines
// 7. Resetting the rate limiter
// 8. Clearing the DNS cache
// Safe to call multiple times; subsequent calls are no-ops. Does not wait for goroutines to exit;
// caller should wait if needed using context or other synchronization.
func (c *Common) Stop() {
	if c.Cancel != nil {
		c.Cancel()
	}

	if c.TunnelPool != nil {
		active := c.TunnelPool.Active()
		c.TunnelPool.Close()
		c.Logger.Debug("Tunnel connection closed: pool active %v", active)
	}

	c.TargetUDPSession.Range(func(key, value any) bool {
		if conn, ok := value.(*net.UDPConn); ok {
			conn.Close()
		}
		c.TargetUDPSession.Delete(key)
		return true
	})

	if c.TargetUDPConn != nil {
		c.TargetUDPConn.Close()
		c.Logger.Debug("Target connection closed: %v", c.TargetUDPConn.LocalAddr())
	}

	if c.TunnelUDPConn != nil {
		c.TunnelUDPConn.Close()
		c.Logger.Debug("Tunnel connection closed: %v", c.TunnelUDPConn.LocalAddr())
	}

	if c.ControlConn != nil {
		c.ControlConn.Close()
		c.Logger.Debug("Control connection closed: %v", c.ControlConn.LocalAddr())
	}

	if c.TargetListener != nil {
		c.TargetListener.Close()
		c.Logger.Debug("Target listener closed: %v", c.TargetListener.Addr())
	}

	if c.TunnelListener != nil {
		c.TunnelListener.Close()
		c.Logger.Debug("Tunnel listener closed: %v", c.TunnelListener.Addr())
	}

	Drain(c.SignalChan)
	Drain(c.WriteChan)
	Drain(c.VerifyChan)

	if c.RateLimiter != nil {
		c.RateLimiter.Reset()
	}

	c.ClearCache()
}

// CommonShutdown executes stopFunc in a background goroutine and waits for it to complete before the
// provided context expires. Returns nil when stopFunc completes successfully, or a context error if the
// shutdown deadline is exceeded. Useful for coordinating graceful shutdown with a deadline to prevent
// indefinite blocking on stuck Stop() calls.
func (c *Common) CommonShutdown(ctx context.Context, stopFunc func()) error {
	done := make(chan struct{})
	go func() {
		defer close(done) // signal completion when stopFunc returns
		stopFunc()        // run the shutdown function
	}()

	select {
	case <-ctx.Done():
		// deadline exceeded or context cancelled
		return fmt.Errorf("CommonShutdown: context error: %w", ctx.Err())
	case <-done:
		// stopFunc completed successfully
		return nil
	}
}
