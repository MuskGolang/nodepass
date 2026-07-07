// handshake.go implements the server side of the HTTP tunnel handshake. The
// server listens for a single authenticated GET request, responds with the
// data-flow direction, pool capacity cap, TLS code, and pool type as JSON, then records
// the client IP and transitions to pool mode.
package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/NodePassProject/nodepass/internal/common"
)

// TunnelHandshake starts a temporary HTTPS server on TunnelListener to perform
// the initial HTTP-based negotiation with the client. The handshake:
// 1. Waits for an authenticated GET request (Bearer token validation)
// 2. Sends back JSON configuration (data flow direction, max pool capacity, TLS code, pool type)
// 3. Records the client IP for source IP validation in BasePool
// 4. Optionally regenerates the TLS certificate if TLSCode is "1"
// 5. Closes the HTTP server and re-creates the TCP listener for pool mode
//
// Returns an error if the context is cancelled before the handshake completes.
func (s *Server) TunnelHandshake() error {
	var clientIP string
	done := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Connection", "close")
			if r.URL.Path != "/" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") || !s.VerifyAuthToken(strings.TrimPrefix(auth, "Bearer ")) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			clientIP = r.RemoteAddr
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"flow": s.DataFlow,
				"max":  s.MaxPoolCapacity,
				"tls":  s.TLSCode,
				"type": s.PoolType,
			})

			s.Logger.Info("Sending tunnel config: FLOW=%v|MAX=%v|TLS=%v|TYPE=%v",
				s.DataFlow, s.MaxPoolCapacity, s.TLSCode, s.PoolType)

			close(done)
		case http.MethodConnect:
			if !s.VerifyPreAuth(r) {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			s.HandlePreAuth(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	})

	tlsConfig := s.TLSConfig
	if tlsConfig == nil {
		tlsConfig, _ = common.NewTLSConfig()
	}

	if len(tlsConfig.Certificates) > 0 && len(tlsConfig.Certificates[0].Certificate) > 0 {
		fingerprint := s.FormatCertFingerprint(tlsConfig.Certificates[0].Certificate[0])
		s.Logger.Info("TLS code-1: RAM cert prepared with sha256 fingerprint: %v", fingerprint)
	}

	server := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
		ErrorLog:  s.Logger.StdLogger(),
	}
	go server.ServeTLS(s.TunnelListener, "", "")

	select {
	case <-done:
		server.Close()
		s.ClientIP = clientIP
		if s.TLSCode == "1" {
			if newTLSConfig, err := common.NewTLSConfig(); err == nil {
				newTLSConfig.MinVersion = tls.VersionTLS13
				s.TLSConfig = newTLSConfig
				s.Logger.Info("TLS code-1: RAM cert regenerated with TLS 1.3")
			} else {
				s.Logger.Warn("Failed to regenerate RAM cert: %v", err)
			}
		}

		s.TunnelListener, _ = net.ListenTCP("tcp", s.TunnelTCPAddr)
		return nil
	case <-s.Ctx.Done():
		server.Close()
		return fmt.Errorf("TunnelHandshake: context canceled")
	}
}
