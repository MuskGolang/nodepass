// pool.go initialises the client-side tunnel connection pool after a successful
// handshake. The pool backend is selected by the server and can use TCP, QUIC,
// WebSocket, or HTTP/2 while presenting the same TransportPool interface to the
// tunnel data paths.
package client

import (
	"fmt"
	"net"

	"github.com/NodePassProject/nodepass/internal/common"
	"github.com/NodePassProject/nph2"
	"github.com/NodePassProject/npws"
	"github.com/NodePassProject/pool"
	"github.com/NodePassProject/quic"
)

// InitTunnelPool creates and initializes the client-side pool selected by PoolType.
// PoolType values are:
//   - "0": TCP pool
//   - "1": QUIC pool
//   - "2": WebSocket pool
//   - "3": HTTP/2 pool
//
// All implementations are adapted to common.TransportPool, so the rest of the
// client does not need to know which transport backend was negotiated.
func (c *Client) InitTunnelPool() error {
	switch c.PoolType {
	case "0":
		tcpPool := pool.NewClientPool(
			c.MinPoolCapacity,
			c.MaxPoolCapacity,
			common.MinPoolInterval,
			common.MaxPoolInterval,
			common.ReportInterval,
			c.TLSCode,
			c.ServerName,
			func() (net.Conn, error) {
				tcpAddr, err := c.GetTunnelTCPAddr()
				if err != nil {
					return nil, err
				}
				return net.DialTimeout("tcp", tcpAddr.String(), common.TCPDialTimeout)
			})
		go tcpPool.ClientManager()
		c.TunnelPool = tcpPool
	case "1":
		quicPool := quic.NewClientPool(
			c.MinPoolCapacity,
			c.MaxPoolCapacity,
			common.MinPoolInterval,
			common.MaxPoolInterval,
			common.ReportInterval,
			c.TLSCode,
			c.ServerName,
			func() (string, error) {
				udpAddr, err := c.GetTunnelUDPAddr()
				if err != nil {
					return "", err
				}
				return udpAddr.String(), nil
			})
		go quicPool.ClientManager()
		c.TunnelPool = quicPool
	case "2":
		websocketPool := npws.NewClientPool(
			c.MinPoolCapacity,
			c.MaxPoolCapacity,
			common.MinPoolInterval,
			common.MaxPoolInterval,
			common.ReportInterval,
			c.TLSCode,
			c.TunnelAddr)
		go websocketPool.ClientManager()
		c.TunnelPool = websocketPool
	case "3":
		http2Pool := nph2.NewClientPool(
			c.MinPoolCapacity,
			c.MaxPoolCapacity,
			common.MinPoolInterval,
			common.MaxPoolInterval,
			common.ReportInterval,
			c.TLSCode,
			c.ServerName,
			func() (string, error) {
				tcpAddr, err := c.GetTunnelTCPAddr()
				if err != nil {
					return "", err
				}
				return tcpAddr.String(), nil
			})
		go http2Pool.ClientManager()
		c.TunnelPool = http2Pool
	default:
		return fmt.Errorf("InitTunnelPool: unknown pool type: %s", c.PoolType)
	}
	return nil
}
