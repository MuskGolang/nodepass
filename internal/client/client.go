// Package client implements the nodepass tunnel client. It connects outbound
// to a server endpoint, establishes a connection pool or single-mode tunnel,
// and forwards traffic between the local target and the remote server.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NodePassProject/nodepass/internal/common"
)

// Client wraps common.Common, adding client-specific startup and run logic.
// It manages the lifecycle of outbound tunnel connections, including initialization,
// pool management, and graceful shutdown. Supports both single-connection and
// pool-based tunnel modes.
type Client struct{ common.Common }

// NewClient constructs a Client from a parsed URL, optional TLS configuration,
// and a logger. It initializes the embedded Common struct, parses all URL parameters
// into configuration fields, and sets up the rate limiter if configured.
// The returned client is ready to call Run() or Start().
// Returns an error if configuration parsing fails.
func NewClient(parsedURL *url.URL, tlsConfig *tls.Config, logger *common.Logger) (*Client, error) {
	client := &Client{Common: common.NewCommon(logger, tlsConfig)}
	client.ParsedURL = parsedURL

	if err := client.InitConfig(); err != nil {
		return nil, fmt.Errorf("NewClient: initConfig failed: %w", err)
	}
	client.InitRateLimiter()
	return client, nil
}

// Run is the top-level entry point for a client instance. It performs the following:
//   - Logs startup parameters (tunnel address, target, mode, etc.)
//   - Installs OS signal handlers (SIGINT, SIGTERM) for graceful shutdown
//   - Continuously calls Start() and restarts on failure with ServiceCooldown delay
//   - Performs graceful shutdown cleanup when interrupted (closing listeners, flushing pools)
//
// This method blocks until an OS signal is received.
func (c *Client) Run() {
	logInfo := func(prefix string) {
		c.Logger.Info("%v: client://%v@%v/%v?dns=%v&sni=%v&lbs=%v&min=%v&mode=%v&dial=%v&read=%v&rate=%v&slot=%v&proxy=%v&block=%v&notcp=%v&noudp=%v",
			prefix, c.TunnelKey, c.TunnelTCPAddr, c.GetTargetAddrsString(), c.DNSCacheTTL, c.ServerName, c.LBStrategy, c.MinPoolCapacity,
			c.RunMode, c.DialerIP, c.ReadTimeout, c.RateLimit/125000, c.SlotLimit,
			c.ProxyProtocol, c.BlockProtocol, c.DisableTCP, c.DisableUDP)
	}
	logInfo("Client started")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go func() {
		for ctx.Err() == nil {
			if err := c.Start(); err != nil && err != io.EOF {
				c.Logger.Error("Client error: %v", err)
				c.Stop()
				select {
				case <-ctx.Done():
					return
				case <-time.After(common.ServiceCooldown):
				}
				logInfo("Client restart")
			}
		}
	}()

	<-ctx.Done()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), common.ShutdownTimeout)
	defer cancel()
	if err := c.CommonShutdown(shutdownCtx, c.Stop); err != nil {
		c.Logger.Error("Client shutdown error: %v", err)
	} else {
		c.Logger.Info("Client shutdown complete")
	}
}

// Start initializes a fresh context and selects the appropriate run mode based on
// the configured RunMode:
//   - mode "0" (auto): attempts single mode first; falls back to tunnel mode on failure
//   - mode "1" (single): opens a local TLS listener and enters single-connection mode via SingleStart
//   - mode "2" (tunnel): connects to the server and enters pool mode via TunnelStart
//
// For single mode, it wraps the listener with TLS if TLSConfig is configured.
// Returns the first error encountered during initialization or control loop execution.
func (c *Client) Start() error {
	c.InitContext()

	switch c.RunMode {
	case "1":
		if err := c.InitTunnelListener(); err == nil {
			if c.TLSConfig != nil && c.TunnelListener != nil {
				c.TunnelListener = tls.NewListener(c.TunnelListener, c.TLSConfig)
			}
			return c.SingleStart()
		} else {
			return fmt.Errorf("Start: initTunnelListener failed: %w", err)
		}
	case "2":
		return c.TunnelStart()
	default:
		if err := c.InitTunnelListener(); err == nil {
			c.RunMode = "1"
			if c.TLSConfig != nil && c.TunnelListener != nil {
				c.TunnelListener = tls.NewListener(c.TunnelListener, c.TLSConfig)
			}
			return c.SingleStart()
		} else {
			c.RunMode = "2"
			return c.TunnelStart()
		}
	}
}

// SingleStart runs the client in single-connection mode, where one TLS listener
// accepts inbound connections and forwards them directly to the target without
// using a pre-established connection pool. Enters the SingleControl loop for
// handling incoming connections.
func (c *Client) SingleStart() error {
	if err := c.SingleControl(); err != nil {
		return fmt.Errorf("SingleStart: singleControl failed: %w", err)
	}
	return nil
}

// TunnelStart runs the client in pool (tunnel) mode by performing the following steps:
// 1. Performs TunnelHandshake with the server to obtain pool configuration
// 2. Initializes the ApexPool to pre-establish outbound connections
// 3. Waits for the first connection (control connection) via SetControlConn
// 4. Optionally opens a target listener if DataFlow indicates incoming traffic
// 5. Enters TunnelControl loop to manage data exchange between tunnel and target
func (c *Client) TunnelStart() error {
	c.Logger.Info("Pending tunnel handshake...")
	c.HandshakeStart = time.Now()
	if err := c.TunnelHandshake(); err != nil {
		return fmt.Errorf("TunnelStart: tunnelHandshake failed: %w", err)
	}

	if err := c.InitTunnelPool(); err != nil {
		return fmt.Errorf("TunnelStart: initTunnelPool failed: %w", err)
	}

	c.Logger.Info("Getting tunnel pool ready...")
	if err := c.SetControlConn(); err != nil {
		return fmt.Errorf("TunnelStart: setControlConn failed: %w", err)
	}

	if c.DataFlow == "+" {
		if err := c.InitTargetListener(); err != nil {
			return fmt.Errorf("TunnelStart: initTargetListener failed: %w", err)
		}
		go c.TunnelLoop()
	}

	if err := c.TunnelControl(); err != nil {
		return fmt.Errorf("TunnelStart: tunnelControl failed: %w", err)
	}

	return nil
}
