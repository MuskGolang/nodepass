// pool.go initialises the server-side tunnel connection pool after a successful
// handshake. The selected backend accepts or serves TCP, QUIC, WebSocket, or
// HTTP/2 tunnel connections while presenting the same TransportPool interface to
// the tunnel data paths.
package server

import (
	"fmt"

	"github.com/NodePassProject/nodepass/internal/common"
	"github.com/NodePassProject/nph2"
	"github.com/NodePassProject/npws"
	"github.com/NodePassProject/pool"
	"github.com/NodePassProject/quic"
)

// InitTunnelPool creates and initializes the server-side pool selected by PoolType.
// PoolType values are:
//   - "0": TCP pool
//   - "1": QUIC pool
//   - "2": WebSocket pool
//   - "3": HTTP/2 pool
//
// All implementations are adapted to common.TransportPool, so the rest of the
// server does not need to know which transport backend was negotiated.
func (s *Server) InitTunnelPool() error {
	switch s.PoolType {
	case "0":
		tcpPool := pool.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		go tcpPool.ServerManager()
		s.TunnelPool = tcpPool
	case "1":
		quicPool := quic.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelUDPAddr.String(),
			common.ReportInterval)
		go quicPool.ServerManager()
		s.TunnelPool = quicPool
	case "2":
		websocketPool := npws.NewServerPool(
			s.MaxPoolCapacity,
			"",
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		go websocketPool.ServerManager()
		s.TunnelPool = websocketPool
	case "3":
		http2Pool := nph2.NewServerPool(
			s.MaxPoolCapacity,
			s.ClientIP,
			s.TLSConfig,
			s.TunnelListener,
			common.ReportInterval)
		go http2Pool.ServerManager()
		s.TunnelPool = http2Pool
	default:
		return fmt.Errorf("InitTunnelPool: unknown pool type: %s", s.PoolType)
	}
	return nil
}
