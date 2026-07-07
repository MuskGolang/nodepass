// conn.go provides StatConn, a net.Conn wrapper that atomically tracks bytes
// read and written and applies optional token-bucket rate limiting.
package transport

import (
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// ErrNotUDPConn is returned when an operation expects a UDP connection but
// the underlying connection is TCP or another type that doesn't support UDP operations.
var ErrNotUDPConn = errors.New("not a UDP connection")

// StatConn wraps a net.Conn to atomically track bytes read and written in real-time,
// and applies optional token-bucket rate limiting on reads and writes. This allows
// the tunnel to account for traffic and enforce per-connection bandwidth limits.
type StatConn struct {
	Conn net.Conn     // underlying connection (TCP or UDP)
	Rx   *uint64      // pointer to atomic RX byte counter (shared with Common for stats reporting)
	Tx   *uint64      // pointer to atomic TX byte counter (shared with Common for stats reporting)
	Rate *RateLimiter // token-bucket rate limiter; nil means no rate limiting (unlimited)
}

// NewStatConn wraps a connection with traffic accounting and optional rate limiting.
// It enables real-time statistics tracking and bandwidth control on a per-connection basis.
// rx and tx must be valid pointers to atomic uint64 counters shared with the Common stats;
// rate may be nil to disable rate limiting (unlimited bandwidth).
func NewStatConn(conn net.Conn, rx, tx *uint64, rate *RateLimiter) *StatConn {
	return &StatConn{
		Conn: conn,
		Rx:   rx,
		Tx:   tx,
		Rate: rate,
	}
}

// Read reads data from the underlying connection, atomically updates the RX
// byte counter, and applies read-side rate limiting if configured. The rate
// limiter blocks until tokens are available for the received bytes.
func (sc *StatConn) Read(b []byte) (int, error) {
	n, err := sc.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(sc.Rx, uint64(n))
		if sc.Rate != nil {
			sc.Rate.WaitRead(int64(n))
		}
	}
	return n, err
}

// Write applies write-side rate limiting if configured (blocks until tokens are
// available), writes data to the underlying connection, and atomically updates
// the TX byte counter for statistics tracking.
func (sc *StatConn) Write(b []byte) (int, error) {
	if sc.Rate != nil {
		sc.Rate.WaitWrite(int64(len(b)))
	}
	n, err := sc.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(sc.Tx, uint64(n))
	}
	return n, err
}

// Close closes the underlying connection.
func (sc *StatConn) Close() error {
	return sc.Conn.Close()
}

// LocalAddr returns the local address of the underlying connection.
func (sc *StatConn) LocalAddr() net.Addr {
	return sc.Conn.LocalAddr()
}

// RemoteAddr returns the remote address of the underlying connection.
func (sc *StatConn) RemoteAddr() net.Addr {
	return sc.Conn.RemoteAddr()
}

// SetDeadline sets both read and write deadlines for the underlying connection.
func (sc *StatConn) SetDeadline(t time.Time) error {
	return sc.Conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline for the underlying connection.
func (sc *StatConn) SetReadDeadline(t time.Time) error {
	return sc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the underlying connection.
func (sc *StatConn) SetWriteDeadline(t time.Time) error {
	return sc.Conn.SetWriteDeadline(t)
}

// AsUDPConn attempts to cast the underlying connection to a UDP connection.
func (sc *StatConn) AsUDPConn() (*net.UDPConn, bool) {
	udpConn, ok := sc.Conn.(*net.UDPConn)
	return udpConn, ok
}

// ReadFromUDP reads UDP datagram data from the connection (which must be UDP),
// atomically updates RX statistics, and applies read-side rate limiting if configured.
// Returns ErrNotUDPConn if the underlying connection is not a UDP connection.
func (sc *StatConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if udpConn, ok := sc.AsUDPConn(); ok {
		n, addr, err := udpConn.ReadFromUDP(b)
		if n > 0 {
			atomic.AddUint64(sc.Rx, uint64(n))
			if sc.Rate != nil {
				sc.Rate.WaitRead(int64(n))
			}
		}
		return n, addr, err
	}
	return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: ErrNotUDPConn}
}

// WriteToUDP writes UDP datagram data to the specified address (connection must be UDP),
// applies write-side rate limiting if configured, and atomically updates TX statistics.
// Returns ErrNotUDPConn if the underlying connection is not a UDP connection.
func (sc *StatConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if udpConn, ok := sc.AsUDPConn(); ok {
		if sc.Rate != nil {
			sc.Rate.WaitWrite(int64(len(b)))
		}
		n, err := udpConn.WriteToUDP(b, addr)
		if n > 0 {
			atomic.AddUint64(sc.Tx, uint64(n))
		}
		return n, err
	}
	return 0, &net.OpError{Op: "write", Net: "udp", Err: ErrNotUDPConn}
}
