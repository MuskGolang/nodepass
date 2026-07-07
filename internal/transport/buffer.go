// buffer.go provides pooled byte-slice allocators for TCP and UDP data paths.
// Using sync.Pool avoids per-connection heap allocations during high-throughput
// data exchange.
package transport

import "sync"

// Buffers manages object pools for TCP and UDP data buffers. It reduces garbage
// collection pressure and allocation overhead during high-throughput data exchange
// by reusing fixed-size buffers. Each pool lazily allocates buffers on first use.
type Buffers struct {
	tcpPool *sync.Pool // sync.Pool of *[]byte buffers for TCP data (tcpSize bytes each)
	udpPool *sync.Pool // sync.Pool of *[]byte buffers for UDP data (udpSize bytes each)
	tcpSize int        // size of each TCP buffer
	udpSize int        // size of each UDP buffer
}

// NewBuffers initializes and returns a Buffers instance with TCP and UDP
// object pools configured for the given buffer sizes. Typical values are
// TCPDataBufSize and UDPDataBufSize from the common package. Buffers are
// lazily allocated on first request via the pool's New function.
func NewBuffers(tcpSize, udpSize int) *Buffers {
	b := &Buffers{tcpSize: tcpSize, udpSize: udpSize}
	b.tcpPool = &sync.Pool{
		New: func() any {
			buf := make([]byte, tcpSize)
			return &buf
		},
	}
	b.udpPool = &sync.Pool{
		New: func() any {
			buf := make([]byte, udpSize)
			return &buf
		},
	}
	return b
}

// GetTCPBuffer retrieves a TCP buffer from the pool, creating a new one if necessary.
// The returned buffer has length tcpSize. The caller must return the buffer to the
// pool via PutTCPBuffer after use to avoid memory leaks and allow reuse.
func (b *Buffers) GetTCPBuffer() []byte {
	buf := b.tcpPool.Get().(*[]byte)
	return (*buf)[:b.tcpSize]
}

// PutTCPBuffer returns a TCP buffer to the pool for reuse. Buffers with capacity
// less than tcpSize are discarded to prevent size mismatches on subsequent Get calls.
// It is safe to call with a nil buffer.
func (b *Buffers) PutTCPBuffer(buf []byte) {
	if buf != nil && cap(buf) >= b.tcpSize {
		b.tcpPool.Put(&buf)
	}
}

// GetUDPBuffer retrieves a UDP buffer from the pool, creating a new one if necessary.
// The returned buffer has length udpSize. The caller must return the buffer to the
// pool via PutUDPBuffer after use to avoid memory leaks and allow reuse.
func (b *Buffers) GetUDPBuffer() []byte {
	buf := b.udpPool.Get().(*[]byte)
	return (*buf)[:b.udpSize]
}

// PutUDPBuffer returns a UDP buffer to the pool for reuse. Buffers with capacity
// less than udpSize are discarded to prevent size mismatches on subsequent Get calls.
// It is safe to call with a nil buffer.
func (b *Buffers) PutUDPBuffer(buf []byte) {
	if buf != nil && cap(buf) >= b.udpSize {
		b.udpPool.Put(&buf)
	}
}
