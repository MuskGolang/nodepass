// handshake.go implements the HTTP-based tunnel handshake that the client
// performs before establishing its connection pool. The server returns the
// data-flow direction, pool capacity cap, TLS code, and pool type as JSON.
package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
)

// TunnelHandshake performs the initial HTTP-based handshake with the tunnel server.
// It sends an authenticated GET request (with Bearer token) to the server and
// receives JSON configuration containing:
//   - flow: data flow direction ("+" for upstream, "-" for downstream)
//   - max: maximum connection pool capacity agreed by server
//   - tls: TLS code indicating certificate verification mode
//   - type: tunnel pool backend selected by the server
//
// The HTTP transport uses InsecureSkipVerify because the server may use an
// ephemeral self-signed certificate during the handshake. This method must be
// called before InitTunnelPool to obtain the necessary configuration.
func (c *Client) TunnelHandshake() error {
	req, _ := http.NewRequest(http.MethodGet, "https://"+c.TunnelAddr+"/", nil)
	req.Host = c.ServerName
	req.Header.Set("Authorization", "Bearer "+c.GenerateAuthToken())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("TunnelHandshake: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("TunnelHandshake: status %d", resp.StatusCode)
	}

	var config struct {
		Flow string `json:"flow"`
		Max  int    `json:"max"`
		TLS  string `json:"tls"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("TunnelHandshake: %w", err)
	}

	c.DataFlow = config.Flow
	c.MaxPoolCapacity = config.Max
	c.TLSCode = config.TLS
	c.PoolType = config.Type

	c.Logger.Info("Loading tunnel config: FLOW=%v|MAX=%v|TLS=%v|TYPE=%v",
		c.DataFlow, c.MaxPoolCapacity, c.TLSCode, c.PoolType)
	return nil
}
