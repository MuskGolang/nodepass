// tunnel.go contains the pooled-mode data-path entry point (TunnelLoop),
// the TCP and UDP data loops, and the signal dispatcher (TunnelOnce).
// It handles both inbound target connections (server-side) and outbound
// pool connections (client-side) across TCP and UDP.
package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/NodePassProject/nodepass/internal/transport"
)

// TunnelLoop blocks until the tunnel pool is ready, optionally waits for TLS fingerprint verification
// to complete (TLS code-1 feature), then starts the TCP and/or UDP data loops concurrently.
// Returns immediately when context is cancelled. Entry point for pooled-mode data transfer.
func (c *Common) TunnelLoop() {
	for c.Ctx.Err() == nil {
		if c.TunnelPool.Ready() {
			if c.TLSCode == "1" {
				select {
				case <-c.VerifyChan:
				case <-c.Ctx.Done():
					return
				}
			}

			if c.TargetListener != nil || c.DisableTCP != "1" {
				go c.TunnelTCPLoop()
			}
			if c.TargetUDPConn != nil || c.DisableUDP != "1" {
				go c.TunnelUDPLoop()
			}
			return
		}

		select {
		case <-c.Ctx.Done():
			return
		case <-time.After(ContextCheckInterval):
		}
	}
}

// TunnelTCPLoop is the TCP data loop for pooled mode (server-side). For each incoming connection:
// 1. Wraps with statistics tracking and rate limiting
// 2. Enforces TCP slot limits
// 3. Detects and blocks unwanted protocols if enabled
// 4. Retrieves a tunnel pool connection
// 5. Sends a "tcp" signal to the client-side to initiate the corresponding transfer
// 6. Runs DataExchange between the target and tunnel connection concurrently
// Returns when listener closes or context is cancelled.
func (c *Common) TunnelTCPLoop() {
	for c.Ctx.Err() == nil {
		targetConn, err := c.TargetListener.Accept()
		if err != nil {
			if c.Ctx.Err() != nil || err == net.ErrClosed {
				return
			}
			c.Logger.Error("TunnelTCPLoop: accept failed: %v", err)

			select {
			case <-c.Ctx.Done():
				return
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		targetConn = transport.NewStatConn(targetConn, &c.TCPRX, &c.TCPTX, c.RateLimiter)
		c.Logger.Debug("Target connection: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())

		go func(targetConn net.Conn) {
			defer func() {
				if targetConn != nil {
					targetConn.Close()
				}
			}()

			if !c.TryAcquireSlot(false) {
				c.Logger.Error("TunnelTCPLoop: TCP slot limit reached: %v/%v", c.TCPSlot, c.SlotLimit)
				return
			}
			defer c.ReleaseSlot(false)

			protocol, wrappedConn := c.DetectBlockProtocol(targetConn)
			if protocol != "" {
				c.Logger.Warn("TunnelTCPLoop: blocked %v protocol from %v", protocol, targetConn.RemoteAddr())
				return
			}
			targetConn = wrappedConn

			id, remoteConn, err := c.TunnelPool.IncomingGet(PoolGetTimeout)
			if err != nil {
				c.Logger.Warn("TunnelTCPLoop: request timeout: %v", err)
				return
			}

			c.Logger.Debug("Tunnel connection: get %v <- pool active %v", id, c.TunnelPool.Active())

			defer func() {
				if remoteConn != nil {
					remoteConn.Close()
					c.Logger.Debug("Tunnel connection: closed %v", id)
				}
			}()

			c.Logger.Debug("Tunnel connection: %v <-> %v", remoteConn.LocalAddr(), remoteConn.RemoteAddr())

			if c.Ctx.Err() == nil && c.ControlConn != nil {
				signalData, _ := json.Marshal(Signal{
					ActionType: "tcp",
					RemoteAddr: targetConn.RemoteAddr().String(),
					PoolConnID: id,
				})
				c.WriteChan <- c.Encode(signalData)
			}

			c.Logger.Debug("TCP launch signal: cid %v -> %v", id, c.ControlConn.RemoteAddr())

			buffer1 := c.GetTCPBuffer()
			buffer2 := c.GetTCPBuffer()
			defer func() {
				c.PutTCPBuffer(buffer1)
				c.PutTCPBuffer(buffer2)
			}()

			c.Logger.Info("Starting exchange: %v <-> %v", targetConn.RemoteAddr(), remoteConn.RemoteAddr())
			c.Logger.Info("Exchange complete: %v", transport.DataExchange(targetConn, remoteConn, c.ReadTimeout, buffer1, buffer2))
		}(targetConn)
	}
}

// TunnelUDPLoop is the UDP data loop for pooled mode (server-side). For each inbound datagram:
// 1. Creates a session key from the client address
// 2. For new sessions: retrieves a pool connection, stores it, and spawns a background reader
// 3. For existing sessions: reuses the stored connection
// 4. Enforces UDP slot limits
// 5. Sends a "udp" signal to the client-side to initiate the corresponding transfer (new sessions only)
// 6. Writes the datagram to the tunnel connection and reads responses back
// Returns when listener closes or context is cancelled.
func (c *Common) TunnelUDPLoop() {
	for c.Ctx.Err() == nil {
		buffer := c.GetUDPBuffer()

		x, clientAddr, err := c.TargetUDPConn.ReadFromUDP(buffer)
		if err != nil {
			if c.Ctx.Err() != nil || err == net.ErrClosed {
				c.PutUDPBuffer(buffer)
				return
			}
			c.Logger.Error("TunnelUDPLoop: readFromUDP failed: %v", err)
			c.PutUDPBuffer(buffer)

			select {
			case <-c.Ctx.Done():
				return
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		c.Logger.Debug("Target connection: %v <-> %v", c.TargetUDPConn.LocalAddr(), clientAddr)

		var id string
		var remoteConn net.Conn
		sessionKey := clientAddr.String()

		if session, ok := c.TargetUDPSession.Load(sessionKey); ok {
			remoteConn = session.(net.Conn)
			c.Logger.Debug("Using UDP session: %v <-> %v", remoteConn.LocalAddr(), remoteConn.RemoteAddr())
		} else {
			if !c.TryAcquireSlot(true) {
				c.Logger.Error("TunnelUDPLoop: UDP slot limit reached: %v/%v", c.UDPSlot, c.SlotLimit)
				c.PutUDPBuffer(buffer)
				continue
			}

			id, remoteConn, err = c.TunnelPool.IncomingGet(PoolGetTimeout)
			if err != nil {
				c.Logger.Warn("TunnelUDPLoop: request timeout: %v", err)
				c.ReleaseSlot(true)
				c.PutUDPBuffer(buffer)
				continue
			}
			c.TargetUDPSession.Store(sessionKey, remoteConn)
			c.Logger.Debug("Tunnel connection: get %v <- pool active %v", id, c.TunnelPool.Active())
			c.Logger.Debug("Tunnel connection: %v <-> %v", remoteConn.LocalAddr(), remoteConn.RemoteAddr())

			go func(remoteConn net.Conn, clientAddr *net.UDPAddr, sessionKey, id string) {
				defer func() {
					c.TargetUDPSession.Delete(sessionKey)
					c.ReleaseSlot(true)

					if remoteConn != nil {
						remoteConn.Close()
						c.Logger.Debug("Tunnel connection: closed %v", id)
					}
				}()

				buffer := c.GetUDPBuffer()
				defer c.PutUDPBuffer(buffer)

				for c.Ctx.Err() == nil {
					x, err := transport.ReadUDPFrame(remoteConn, buffer, UDPReadTimeout)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							c.Logger.Debug("UDP session abort: %v", err)
						} else if err != io.EOF && err != io.ErrUnexpectedEOF {
							c.Logger.Error("TunnelUDPLoop: read from tunnel failed: %v", err)
						}
						return
					}

					_, err = c.TargetUDPConn.WriteToUDP(buffer[:x], clientAddr)
					if err != nil {
						if err != io.EOF {
							c.Logger.Error("TunnelUDPLoop: writeToUDP failed: %v", err)
						}
						return
					}
					c.Logger.Debug("Transfer complete: %v <-> %v", remoteConn.LocalAddr(), c.TargetUDPConn.LocalAddr())
				}
			}(remoteConn, clientAddr, sessionKey, id)

			if c.Ctx.Err() == nil && c.ControlConn != nil {
				signalData, _ := json.Marshal(Signal{
					ActionType: "udp",
					RemoteAddr: clientAddr.String(),
					PoolConnID: id,
				})
				c.WriteChan <- c.Encode(signalData)
			}

			c.Logger.Debug("UDP launch signal: cid %v -> %v", id, c.ControlConn.RemoteAddr())
			c.Logger.Debug("Starting transfer: %v <-> %v", remoteConn.LocalAddr(), c.TargetUDPConn.LocalAddr())
		}

		if err = transport.WriteUDPFrame(remoteConn, buffer[:x]); err != nil {
			if err != io.EOF {
				c.Logger.Error("TunnelUDPLoop: write to tunnel failed: %v", err)
			}
			c.TargetUDPSession.Delete(sessionKey)
			remoteConn.Close()
			c.PutUDPBuffer(buffer)
			continue
		}

		c.Logger.Debug("Transfer complete: %v <-> %v", remoteConn.LocalAddr(), c.TargetUDPConn.LocalAddr())
		c.PutUDPBuffer(buffer)
	}
}

// TunnelOnce is the signal dispatcher loop for pooled mode (client-side). Reads from SignalChan
// and dispatches each Signal to the appropriate handler based on ActionType:
//   - "verify": TLS code-1 fingerprint verification (calls OutgoingVerify)
//   - "tcp": initiate TCP transfer (calls TunnelTCPOnce)
//   - "udp": initiate UDP transfer (calls TunnelUDPOnce)
//   - "flush": trigger pool flush (closes and re-establishes connections)
//   - "ping": reply with "pong" signal (health check response)
//   - "pong": log CHECK_POINT event with metrics (latency, pool active count, slot/byte counters)
func (c *Common) TunnelOnce() error {
	for c.Ctx.Err() == nil {
		if !c.TunnelPool.Ready() {
			select {
			case <-c.Ctx.Done():
				return fmt.Errorf("TunnelOnce: context error: %w", c.Ctx.Err())
			case <-time.After(ContextCheckInterval):
			}
			continue
		}

		select {
		case <-c.Ctx.Done():
			return fmt.Errorf("TunnelOnce: context error: %w", c.Ctx.Err())
		case signal := <-c.SignalChan:
			switch signal.ActionType {
			case "verify":
				if c.TLSCode == "1" {
					go c.OutgoingVerify(signal)
				}
			case "tcp":
				if c.DisableTCP != "1" {
					go c.TunnelTCPOnce(signal)
				}
			case "udp":
				if c.DisableUDP != "1" {
					go c.TunnelUDPOnce(signal)
				}
			case "flush":
				go func() {
					c.TunnelPool.Flush()
					c.TunnelPool.ResetError()

					select {
					case <-c.Ctx.Done():
						return
					case <-time.After(ReportInterval):
					}

					c.Logger.Debug("Tunnel pool flushed: %v active connections", c.TunnelPool.Active())
				}()
			case "ping":
				if c.Ctx.Err() == nil && c.ControlConn != nil {
					signalData, _ := json.Marshal(Signal{ActionType: "pong"})
					c.WriteChan <- c.Encode(signalData)
				}
			case "pong":
				c.Logger.Event("CHECK_POINT|MODE=%v|PING=%vms|POOL=%v|TCPS=%v|UDPS=%v|TCPRX=%v|TCPTX=%v|UDPRX=%v|UDPTX=%v",
					c.RunMode, time.Since(c.CheckPoint).Milliseconds(), c.TunnelPool.Active(),
					atomic.LoadInt32(&c.TCPSlot), atomic.LoadInt32(&c.UDPSlot),
					atomic.LoadUint64(&c.TCPRX), atomic.LoadUint64(&c.TCPTX),
					atomic.LoadUint64(&c.UDPRX), atomic.LoadUint64(&c.UDPTX))
			default:
			}
		}
	}

	return fmt.Errorf("TunnelOnce: context error: %w", c.Ctx.Err())
}

// TunnelTCPOnce handles a single TCP transfer initiated by a remote "tcp" signal (client-side).
// 1. Retrieves the designated pool connection by ID
// 2. Enforces TCP slot limits
// 3. Dials a target using load-balanced rotation strategy
// 4. Wraps target connection with statistics tracking and rate limiting
// 5. Optionally emits PROXY Protocol v1 header with original client address
// 6. Runs DataExchange between tunnel and target concurrently
// Called as a background goroutine from TunnelOnce.
func (c *Common) TunnelTCPOnce(signal Signal) {
	id := signal.PoolConnID
	c.Logger.Debug("TCP launch signal: cid %v <- %v", id, c.ControlConn.RemoteAddr())

	remoteConn, err := c.TunnelPool.OutgoingGet(id, PoolGetTimeout)
	if err != nil {
		c.Logger.Error("TunnelTCPOnce: request timeout: %v", err)
		c.TunnelPool.AddError()
		return
	}

	c.Logger.Debug("Tunnel connection: get %v <- pool active %v", id, c.TunnelPool.Active())

	defer func() {
		if remoteConn != nil {
			remoteConn.Close()
			c.Logger.Debug("Tunnel connection: closed %v", id)
		}
	}()

	c.Logger.Debug("Tunnel connection: %v <-> %v", remoteConn.LocalAddr(), remoteConn.RemoteAddr())

	if !c.TryAcquireSlot(false) {
		c.Logger.Error("TunnelTCPOnce: TCP slot limit reached: %v/%v", c.TCPSlot, c.SlotLimit)
		return
	}

	defer c.ReleaseSlot(false)

	targetConn, err := c.DialWithRotation("tcp", TCPDialTimeout)
	if err != nil {
		c.Logger.Error("TunnelTCPOnce: dialWithRotation failed: %v", err)
		return
	}

	defer func() {
		if targetConn != nil {
			targetConn.Close()
		}
	}()

	targetConn = transport.NewStatConn(targetConn, &c.TCPRX, &c.TCPTX, c.RateLimiter)
	c.Logger.Debug("Target connection: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())

	if err := c.SendProxyV1Header(signal.RemoteAddr, targetConn); err != nil {
		c.Logger.Error("TunnelTCPOnce: sendProxyV1Header failed: %v", err)
		return
	}

	buffer1 := c.GetTCPBuffer()
	buffer2 := c.GetTCPBuffer()
	defer func() {
		c.PutTCPBuffer(buffer1)
		c.PutTCPBuffer(buffer2)
	}()

	c.Logger.Info("Starting exchange: %v <-> %v", remoteConn.RemoteAddr(), targetConn.RemoteAddr())
	c.Logger.Info("Exchange complete: %v", transport.DataExchange(remoteConn, targetConn, c.ReadTimeout, buffer1, buffer2))
}

// TunnelUDPOnce handles a single UDP flow initiated by a remote "udp" signal (client-side).
// For new sessions:
// 1. Enforces UDP slot limits
// 2. Dials a target using load-balanced rotation strategy
// 3. Wraps with statistics tracking and rate limiting
// 4. Stores the connection in TargetUDPSession by key
// 5. Spawns two bidirectional forwarding goroutines (tunnel→target and target→tunnel)
// For existing sessions: reuses the stored connection for forwarding datagrams.
// Called as a background goroutine from TunnelOnce.
func (c *Common) TunnelUDPOnce(signal Signal) {
	id := signal.PoolConnID
	c.Logger.Debug("UDP launch signal: cid %v <- %v", id, c.ControlConn.RemoteAddr())

	remoteConn, err := c.TunnelPool.OutgoingGet(id, PoolGetTimeout)
	if err != nil {
		c.Logger.Error("TunnelUDPOnce: request timeout: %v", err)
		c.TunnelPool.AddError()
		return
	}

	c.Logger.Debug("Tunnel connection: get %v <- pool active %v", id, c.TunnelPool.Active())
	c.Logger.Debug("Tunnel connection: %v <-> %v", remoteConn.LocalAddr(), remoteConn.RemoteAddr())

	defer func() {
		if remoteConn != nil {
			remoteConn.Close()
			c.Logger.Debug("Tunnel connection: closed %v", id)
		}
	}()

	var targetConn net.Conn
	sessionKey := signal.RemoteAddr
	isNewSession := false

	if session, ok := c.TargetUDPSession.Load(sessionKey); ok {
		targetConn = session.(net.Conn)
		c.Logger.Debug("Using UDP session: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())
	} else {
		isNewSession = true

		if !c.TryAcquireSlot(true) {
			c.Logger.Error("TunnelUDPOnce: UDP slot limit reached: %v/%v", c.UDPSlot, c.SlotLimit)
			return
		}

		newSession, err := c.DialWithRotation("udp", UDPDialTimeout)
		if err != nil {
			c.Logger.Error("TunnelUDPOnce: dialWithRotation failed: %v", err)
			c.ReleaseSlot(true)
			return
		}
		targetConn = transport.NewStatConn(newSession, &c.UDPRX, &c.UDPTX, c.RateLimiter)
		c.TargetUDPSession.Store(sessionKey, targetConn)
		c.Logger.Debug("Target connection: %v <-> %v", targetConn.LocalAddr(), targetConn.RemoteAddr())
	}

	if isNewSession {
		defer func() {
			c.TargetUDPSession.Delete(sessionKey)
			if targetConn != nil {
				targetConn.Close()
			}
			c.ReleaseSlot(true)
		}()
	}

	c.Logger.Debug("Starting transfer: %v <-> %v", remoteConn.LocalAddr(), targetConn.LocalAddr())

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()

		buffer := c.GetUDPBuffer()
		defer c.PutUDPBuffer(buffer)

		for c.Ctx.Err() == nil {
			x, err := transport.ReadUDPFrame(remoteConn, buffer, UDPReadTimeout)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.Logger.Debug("UDP session abort: %v", err)
				} else if err != io.EOF && err != io.ErrUnexpectedEOF {
					c.Logger.Error("TunnelUDPOnce: read from tunnel failed: %v", err)
				}
				return
			}

			_, err = targetConn.Write(buffer[:x])
			if err != nil {
				if err != io.EOF {
					c.Logger.Error("TunnelUDPOnce: write to target failed: %v", err)
				}
				return
			}

			c.Logger.Debug("Transfer complete: %v <-> %v", remoteConn.LocalAddr(), targetConn.LocalAddr())
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()

		buffer := c.GetUDPBuffer()
		defer c.PutUDPBuffer(buffer)

		for c.Ctx.Err() == nil {
			if UDPReadTimeout > 0 {
				targetConn.SetReadDeadline(time.Now().Add(UDPReadTimeout))
			}
			x, err := targetConn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.Logger.Debug("UDP session abort: %v", err)
				} else if err != io.EOF {
					c.Logger.Error("TunnelUDPOnce: read from target failed: %v", err)
				}
				return
			}

			if err = transport.WriteUDPFrame(remoteConn, buffer[:x]); err != nil {
				if err != io.EOF {
					c.Logger.Error("TunnelUDPOnce: write to tunnel failed: %v", err)
				}
				return
			}

			c.Logger.Debug("Transfer complete: %v <-> %v", targetConn.LocalAddr(), remoteConn.LocalAddr())
		}
	}()

	<-done
}
