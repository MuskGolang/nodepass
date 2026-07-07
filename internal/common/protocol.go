// protocol.go contains helpers for protocol-level operations: emitting PROXY
// Protocol v1 headers and detecting/blocking unwanted application protocols
// (SOCKS4/5, plain HTTP, TLS ClientHello) at the connection boundary.
package common

import (
	"bufio"
	"fmt"
	"net"
)

// SendProxyV1Header writes a PROXY Protocol v1 header to the outbound connection when ProxyProtocol == "1".
// The header encodes the original client address (from the ip parameter) and the target server address
// so that upstream proxies or load balancers can log the real client IP and reconstruct the original flow.
// Does nothing (returns nil) when ProxyProtocol is not "1", allowing transparent passthrough without headers.
// Header format: "PROXY TCP4|TCP6 <srcIP> <dstIP> <srcPort> <dstPort>\r\n"
func (c *Common) SendProxyV1Header(ip string, conn net.Conn) error {
	if c.ProxyProtocol != "1" {
		return nil
	}

	clientAddr, err := net.ResolveTCPAddr("tcp", ip)
	if err != nil {
		return fmt.Errorf("SendProxyV1Header: resolveTCPAddr failed: %w", err)
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("SendProxyV1Header: remote address is not TCPAddr")
	}

	var protocol string
	switch {
	case clientAddr.IP.To4() != nil && remoteAddr.IP.To4() != nil:
		protocol = "TCP4"
	case clientAddr.IP.To16() != nil && remoteAddr.IP.To16() != nil:
		protocol = "TCP6"
	default:
		return fmt.Errorf("SendProxyV1Header: unsupported IP protocol for PROXY v1")
	}

	if _, err = fmt.Fprintf(conn, "PROXY %s %s %s %d %d\r\n",
		protocol,
		clientAddr.IP.String(),
		remoteAddr.IP.String(),
		clientAddr.Port,
		remoteAddr.Port); err != nil {
		return fmt.Errorf("SendProxyV1Header: fprintf failed: %w", err)
	}

	return nil
}

// DetectBlockProtocol peeks at the first 8 bytes of a connection and identifies the application protocol
// from the byte signature (SOCKS4, SOCKS5, HTTP, or TLS). If the detected protocol is enabled in BlockProtocol
// bitmask, returns the protocol name and the caller should drop the connection.
// The returned net.Conn is always wrapped with a ReaderConn containing a *bufio.Reader so that peeked bytes
// are replayed correctly on subsequent reads (preventing data loss during protocol detection).
// Protocol signatures:
//   - SOCKS4: first byte 0x04, second byte 0x01 or 0x02
//   - SOCKS5: first byte 0x05, second byte 0x01-0x03
//   - HTTP: first byte 'A'-'Z' (method), followed by space
//   - TLS: first byte 0x16 (TLS record type: handshake)
func (c *Common) DetectBlockProtocol(conn net.Conn) (string, net.Conn) {
	if !c.BlockSOCKS && !c.BlockHTTP && !c.BlockTLS {
		return "", conn
	}

	reader := bufio.NewReader(conn)
	b, err := reader.Peek(8)
	if err != nil || len(b) < 1 {
		return "", &ReaderConn{Conn: conn, Reader: reader}
	}

	if c.BlockSOCKS && len(b) >= 2 {
		if b[0] == 0x04 && (b[1] == 0x01 || b[1] == 0x02) {
			return "SOCKS4", &ReaderConn{Conn: conn, Reader: reader}
		}
		if b[0] == 0x05 && b[1] >= 0x01 && b[1] <= 0x03 {
			return "SOCKS5", &ReaderConn{Conn: conn, Reader: reader}
		}
	}

	if c.BlockHTTP && len(b) >= 4 && b[0] >= 'A' && b[0] <= 'Z' {
		for i, c := range b[1:] {
			if c == ' ' {
				return "HTTP", &ReaderConn{Conn: conn, Reader: reader}
			}
			if c < 'A' || c > 'Z' || i >= 7 {
				break
			}
		}
	}

	if c.BlockTLS && b[0] == 0x16 {
		return "TLS", &ReaderConn{Conn: conn, Reader: reader}
	}

	return "", &ReaderConn{Conn: conn, Reader: reader}
}
