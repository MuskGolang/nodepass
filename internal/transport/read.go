// read.go provides TimeoutReader, which sets a per-Read deadline to detect
// idle connections in UDP sessions and long-lived control connections.
package transport

import (
	"io"
	"net"
	"time"
)

// TimeoutReader wraps a net.Conn and sets a per-Read deadline to detect idle
// or stalled connections. It is used in UDP sessions and control connections where
// inactivity should trigger a timeout error. The timeout applies to each individual
// Read call, not cumulative reads.
type TimeoutReader struct {
	Conn    net.Conn      // underlying connection to read from
	Timeout time.Duration // per-read deadline; 0 disables deadline setting
}

// NewTimeoutReader wraps a connection with a timeout-enforcing io.Reader that sets
// a per-Read deadline. A zero timeout disables deadline enforcement (no idle detection).
// Returns an io.Reader that can be used with io.Copy or similar functions.
func NewTimeoutReader(conn net.Conn, timeout time.Duration) io.Reader {
	return &TimeoutReader{Conn: conn, Timeout: timeout}
}

// Read reads data from the underlying connection with a timeout deadline applied
// before each read (if Timeout > 0). Returns net.Error with Timeout() == true if
// the per-read deadline expires during the read operation.
func (tr *TimeoutReader) Read(b []byte) (int, error) {
	if tr.Timeout > 0 {
		tr.Conn.SetReadDeadline(time.Now().Add(tr.Timeout))
	}
	return tr.Conn.Read(b)
}
