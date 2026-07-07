// single.go implements single-connection mode: the periodic event loop and
// TCP/UDP data paths. In single mode each accepted connection is immediately
// paired with a fresh dial to the target without a pre-established pool.
package common

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/NodePassProject/nodepass/internal/transport"
)

// SingleEventLoop emits periodic CHECK_POINT metric events on ReportInterval ticker for the lifetime of the tunnel.
// Each event logs: RunMode, latency probe result (ProbeBestTarget), pool count (0 for single mode),
// TCP/UDP slot counts, and byte counters (TCPRX/TCPTX/UDPRX/UDPTX) for monitoring and metrics extraction.
func (c *Common) SingleEventLoop() error {
	ticker := time.NewTicker(ReportInterval)
	defer ticker.Stop()

	for c.Ctx.Err() == nil {
		c.Logger.Event("CHECK_POINT|MODE=%v|PING=%vms|POOL=0|TCPS=%v|UDPS=%v|TCPRX=%v|TCPTX=%v|UDPRX=%v|UDPTX=%v", c.RunMode, c.ProbeBestTarget(),
			atomic.LoadInt32(&c.TCPSlot), atomic.LoadInt32(&c.UDPSlot),
			atomic.LoadUint64(&c.TCPRX), atomic.LoadUint64(&c.TCPTX),
			atomic.LoadUint64(&c.UDPRX), atomic.LoadUint64(&c.UDPTX))

		select {
		case <-c.Ctx.Done():
			return fmt.Errorf("SingleEventLoop: context error: %w", c.Ctx.Err())
		case <-ticker.C:
		}
	}

	return fmt.Errorf("SingleEventLoop: context error: %w", c.Ctx.Err())
}

// SingleTCPLoop is the main TCP data loop for single-connection mode. For each accepted connection:
// 1. Wraps with statistics tracking and rate limiting
// 2. Enforces TCP slot limits (returning error if limit reached)
// 3. Detects and blocks unwanted protocols (SOCKS, HTTP, TLS) if enabled
// 4. Dials a target using load-balanced rotation strategy
// 5. Optionally emits PROXY Protocol v1 header for real client IP
// 6. Runs DataExchange between client and target concurrently
// Returns error when listener closes or context is cancelled.
func (c *Common) SingleTCPLoop() error {
	for c.Ctx.Err() == nil {
		tunnelConn, err := c.TunnelListener.Accept()
		if err != nil {
			if c.Ctx.Err() != nil || err == net.ErrClosed {
				return fmt.Errorf("SingleTCPLoop: context error: %w", c.Ctx.Err())
			}
			c.Logger.Error("SingleTCPLoop: accept failed: %v", err)

			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("SingleTCPLoop: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		tunnelConn = transport.NewStatConn(tunnelConn, &c.TCPRX, &c.TCPTX, c.RateLimiter)
		c.Logger.Debug("Tunnel connection: %v <-> %v", tunnelConn.LocalAddr(), tunnelConn.RemoteAddr())

		go func(tunnelConn net.Conn) {
			defer func() {
				if tunnelConn != nil {
					tunnelConn.Close()
				}
			}()

			if !c.TryAcquireSlot(false) {
				c.Logger.Error("SingleTCPLoop: TCP slot limit reached: %v/%v", c.TCPSlot, c.SlotLimit)
				return
			}

			defer c.ReleaseSlot(false)

			protocol, wrappedConn := c.DetectBlockProtocol(tunnelConn)
			if protocol != "" {
				c.Logger.Warn("SingleTCPLoop: blocked %v protocol from %v", protocol, tunnelConn.RemoteAddr())
				return
			}
			tunnelConn = wrappedConn

			targetConn, err := c.DialWithRotation("tcp", TCPDialTimeout)
			if err != nil {
				c.Logger.Error("SingleTCPLoop: dialWithRotation failed: %v", err)
				return
			}

			defer func() {
				if targetConn != nil {
					targetConn.Close()
				}
			}()

			c.Logger.Debug("Target connection: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())

			if err := c.SendProxyV1Header(tunnelConn.RemoteAddr().String(), targetConn); err != nil {
				c.Logger.Error("SingleTCPLoop: sendProxyV1Header failed: %v", err)
				return
			}

			buffer1 := c.GetTCPBuffer()
			buffer2 := c.GetTCPBuffer()
			defer func() {
				c.PutTCPBuffer(buffer1)
				c.PutTCPBuffer(buffer2)
			}()

			c.Logger.Info("Starting exchange: %v <-> %v", tunnelConn.RemoteAddr(), targetConn.RemoteAddr())
			c.Logger.Info("Exchange complete: %v", transport.DataExchange(tunnelConn, targetConn, c.ReadTimeout, buffer1, buffer2))
		}(tunnelConn)
	}

	return fmt.Errorf("SingleTCPLoop: context error: %w", c.Ctx.Err())
}

// SingleUDPLoop is the main UDP data loop for single-connection mode. For each inbound datagram:
// 1. Creates a session key from the client source address
// 2. For new sessions: dials a fresh target, stores the connection, and spawns a background reader
// 3. For existing sessions: reuses the stored connection
// 4. Enforces UDP slot limits
// 5. Forwards the datagram to the target and receives responses back to the client
// Returns error when listener closes, persistent read/write failures occur, or context is cancelled.
func (c *Common) SingleUDPLoop() error {
	for c.Ctx.Err() == nil {
		buffer := c.GetUDPBuffer()

		x, clientAddr, err := c.TunnelUDPConn.ReadFromUDP(buffer)
		if err != nil {
			if c.Ctx.Err() != nil || err == net.ErrClosed {
				c.PutUDPBuffer(buffer)
				return fmt.Errorf("SingleUDPLoop: context error: %w", c.Ctx.Err())
			}
			c.Logger.Error("SingleUDPLoop: ReadFromUDP failed: %v", err)

			c.PutUDPBuffer(buffer)
			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("SingleUDPLoop: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		c.Logger.Debug("Tunnel connection: %v <-> %v", c.TunnelUDPConn.LocalAddr(), clientAddr)

		var targetConn net.Conn
		sessionKey := clientAddr.String()

		if session, ok := c.TargetUDPSession.Load(sessionKey); ok {
			targetConn = session.(net.Conn)
			c.Logger.Debug("Using UDP session: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())
		} else {
			if !c.TryAcquireSlot(true) {
				c.Logger.Error("SingleUDPLoop: UDP slot limit reached: %v/%v", c.UDPSlot, c.SlotLimit)
				c.PutUDPBuffer(buffer)
				continue
			}

			newSession, err := c.DialWithRotation("udp", UDPDialTimeout)
			if err != nil {
				c.Logger.Error("SingleUDPLoop: dialWithRotation failed: %v", err)
				c.ReleaseSlot(true)
				c.PutUDPBuffer(buffer)
				continue
			}
			targetConn = newSession
			c.TargetUDPSession.Store(sessionKey, newSession)
			c.Logger.Debug("Target connection: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())

			go func(targetConn net.Conn, clientAddr *net.UDPAddr, sessionKey string) {
				defer func() {
					if targetConn != nil {
						targetConn.Close()
					}
					c.ReleaseSlot(true)
				}()

				buffer := c.GetUDPBuffer()
				defer c.PutUDPBuffer(buffer)
				reader := transport.NewTimeoutReader(targetConn, UDPReadTimeout)

				for c.Ctx.Err() == nil {
					x, err := reader.Read(buffer)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							c.Logger.Debug("UDP session abort: %v", err)
						} else if err.Error() != "EOF" {
							c.Logger.Error("SingleUDPLoop: read from target failed: %v", err)
						}
						c.TargetUDPSession.Delete(sessionKey)
						if targetConn != nil {
							targetConn.Close()
						}
						return
					}

					_, err = c.TunnelUDPConn.WriteToUDP(buffer[:x], clientAddr)
					if err != nil {
						if err.Error() != "EOF" {
							c.Logger.Error("SingleUDPLoop: writeToUDP failed: %v", err)
						}
						c.TargetUDPSession.Delete(sessionKey)
						if targetConn != nil {
							targetConn.Close()
						}
						return
					}
					c.Logger.Debug("Transfer complete: %v <-> %v", c.TunnelUDPConn.LocalAddr(), targetConn.LocalAddr())
				}
			}(targetConn, clientAddr, sessionKey)
		}

		c.Logger.Debug("Starting transfer: %v <-> %v", targetConn.LocalAddr(), c.TunnelUDPConn.LocalAddr())
		_, err = targetConn.Write(buffer[:x])
		if err != nil {
			if err.Error() != "EOF" {
				c.Logger.Error("SingleUDPLoop: write to target failed: %v", err)
			}
			c.TargetUDPSession.Delete(sessionKey)
			if targetConn != nil {
				targetConn.Close()
			}
			c.PutUDPBuffer(buffer)
			return fmt.Errorf("SingleUDPLoop: write to target failed: %w", err)
		}

		c.Logger.Debug("Transfer complete: %v <-> %v", targetConn.LocalAddr(), c.TunnelUDPConn.LocalAddr())
		c.PutUDPBuffer(buffer)
	}

	return fmt.Errorf("SingleUDPLoop: context error: %w", c.Ctx.Err())
}
