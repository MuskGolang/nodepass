// Package server implements the nodepass tunnel server. It listens for
// inbound tunnel connections, manages a connection pool, and forwards traffic
// between the tunnel side and the configured target address(es).
package server

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

// Server wraps common.Common, adding server-specific startup and run logic.
// It manages inbound tunnel connections from clients, maintains a connection pool,
// and forwards traffic between the tunnel and configured target addresses.
// Supports both single-connection and pool-based tunnel modes.
type Server struct{ common.Common }

// NewServer constructs a Server from a parsed URL, TLS code, optional TLS
// configuration, and a logger. It initializes the embedded Common struct, stores
// the TLS code for client handshake negotiation, parses all URL parameters into
// configuration fields, and sets up the rate limiter if configured.
// The returned server is ready to call Run() or Start().
// Returns an error if configuration parsing fails.
func NewServer(parsedURL *url.URL, tlsCode string, tlsConfig *tls.Config, logger *common.Logger) (*Server, error) {
	server := &Server{Common: common.NewCommon(logger, tlsConfig)}
	server.ParsedURL = parsedURL
	server.TLSCode = tlsCode

	if err := server.InitConfig(); err != nil {
		return nil, fmt.Errorf("NewServer: initConfig failed: %w", err)
	}
	server.InitRateLimiter()
	return server, nil
}

// Run is the top-level entry point for a server instance. It performs the following:
//   - Logs startup parameters (tunnel address, target, mode, pool capacity, etc.)
//   - Installs OS signal handlers (SIGINT, SIGTERM) for graceful shutdown
//   - Continuously calls Start() and restarts on failure with ServiceCooldown delay
//   - Performs graceful shutdown cleanup when interrupted (closing listeners, flushing pools)
//
// This method blocks until an OS signal is received.
func (s *Server) Run() {
	logInfo := func(prefix string) {
		s.Logger.Info("%v: server://%v@%v/%v?dns=%v&lbs=%v&max=%v&mode=%v&type=%v&dial=%v&read=%v&rate=%v&slot=%v&proxy=%v&block=%v&notcp=%v&noudp=%v",
			prefix, s.TunnelKey, s.TunnelTCPAddr, s.GetTargetAddrsString(), s.DNSCacheTTL, s.LBStrategy, s.MaxPoolCapacity,
			s.RunMode, s.PoolType, s.DialerIP, s.ReadTimeout, s.RateLimit/125000, s.SlotLimit,
			s.ProxyProtocol, s.BlockProtocol, s.DisableTCP, s.DisableUDP)
	}
	logInfo("Server started")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go func() {
		for ctx.Err() == nil {
			if err := s.Start(); err != nil && err != io.EOF {
				s.Logger.Error("Server error: %v", err)
				s.Stop()
				select {
				case <-ctx.Done():
					return
				case <-time.After(common.ServiceCooldown):
				}
				logInfo("Server restart")
			}
		}
	}()

	<-ctx.Done()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), common.ShutdownTimeout)
	defer cancel()
	if err := s.CommonShutdown(shutdownCtx, s.Stop); err != nil {
		s.Logger.Error("Server shutdown error: %v", err)
	} else {
		s.Logger.Info("Server shutdown complete")
	}
}

// Start initializes a fresh context and determines the run mode based on the
// configured RunMode:
//   - mode "0" (auto): attempts single mode first; falls back to tunnel mode if target listener fails
//   - mode "1" (single): opens a target listener and enters single-connection mode
//   - mode "2" (tunnel): enters pool mode without opening a target listener
//
// The flow direction is set based on mode:
//   - single mode (mode "1"): DataFlow = "-" (server forwards from tunnel to target)
//   - tunnel mode (mode "2"): DataFlow = "+" (server forwards from target to tunnel)
//
// After mode setup, it opens the tunnel listener, performs handshake, initializes
// the pool, and enters TunnelControl. Returns the first error encountered.
func (s *Server) Start() error {
	s.InitContext()

	if err := s.InitTunnelListener(); err != nil {
		return fmt.Errorf("Start: initTunnelListener failed: %w", err)
	}

	if s.TunnelUDPConn != nil {
		s.TunnelUDPConn.Close()
	}

	switch s.RunMode {
	case "1":
		if err := s.InitTargetListener(); err != nil {
			return fmt.Errorf("Start: initTargetListener failed: %w", err)
		}
		s.DataFlow = "-"
	case "2":
		s.DataFlow = "+"
	default:
		if err := s.InitTargetListener(); err == nil {
			s.RunMode = "1"
			s.DataFlow = "-"
		} else {
			s.RunMode = "2"
			s.DataFlow = "+"
		}
	}

	s.Logger.Info("Pending tunnel handshake...")
	s.HandshakeStart = time.Now()
	if err := s.TunnelHandshake(); err != nil {
		return fmt.Errorf("Start: tunnelHandshake failed: %w", err)
	}

	if err := s.InitTunnelPool(); err != nil {
		return fmt.Errorf("Start: initTunnelPool failed: %w", err)
	}

	s.Logger.Info("Getting tunnel pool ready...")
	if err := s.SetControlConn(); err != nil {
		return fmt.Errorf("Start: setControlConn failed: %w", err)
	}

	if s.DataFlow == "-" {
		go s.TunnelLoop()
	}

	if err := s.TunnelControl(); err != nil {
		return fmt.Errorf("Start: tunnelControl failed: %w", err)
	}
	return nil
}
