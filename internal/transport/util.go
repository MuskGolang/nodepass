// util.go provides bidirectional data exchange between two connections and
// length-prefixed UDP frame I/O (WriteUDPFrame/ReadUDPFrame) used across
// the tunnel data paths.
package transport

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// DataExchange performs bidirectional data copying between two connections in parallel.
// It uses pre-allocated buffers to minimize allocations during high-throughput
// data transfer. Key features:
//   - Both directions run concurrently via goroutines (full-duplex)
//   - If idleTimeout > 0: applies per-read deadlines to detect idle connections
//   - If idleTimeout == 0: sends TCP FIN (CloseWrite) on half-close for proper FIN propagation
//   - Clears read deadlines before returning to restore normal behavior
//
// Returns the first non-nil error from either direction, or io.EOF if both
// directions complete successfully. Returns io.ErrUnexpectedEOF if either conn is nil.
func DataExchange(conn1, conn2 net.Conn, idleTimeout time.Duration, buffer1, buffer2 []byte) error {
	if conn1 == nil || conn2 == nil {
		return io.ErrUnexpectedEOF
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	copyData := func(src, dst net.Conn, buffer []byte) {
		defer wg.Done()

		reader := NewTimeoutReader(src, idleTimeout)
		_, err := io.CopyBuffer(dst, reader, buffer)
		errChan <- err

		if idleTimeout == 0 {
			if tcpConn, ok := dst.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			} else {
				dst.Close()
			}
		}
	}

	wg.Add(2)
	go copyData(conn1, conn2, buffer1)
	go copyData(conn2, conn1, buffer2)
	wg.Wait()
	close(errChan)

	if idleTimeout > 0 {
		conn1.SetReadDeadline(time.Time{})
		conn2.SetReadDeadline(time.Time{})
	}

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return io.EOF
}

// WriteUDPFrame writes a UDP datagram with a 2-byte big-endian length header to w.
// The header allows the reader to reconstruct UDP datagram boundaries over a stream-
// oriented TCP connection. Enforces the 65535-byte maximum UDP payload size.
// The frame format is: [length (2 bytes)][data (length bytes)]
// Returns an error if the payload exceeds 65535 bytes or on write failure.
func WriteUDPFrame(w net.Conn, data []byte) error {
	length := len(data)
	if length > 65535 {
		return fmt.Errorf("WriteUDPFrame: datagram too large: %d", length)
	}
	header := [2]byte{byte(length >> 8), byte(length)}
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadUDPFrame reads a length-prefixed UDP datagram from conn into the provided buffer.
// It reads the 2-byte big-endian length header, validates it against buffer capacity,
// then reads the payload atomically using io.ReadFull. If timeout > 0, a read deadline
// is applied. The frame format is: [length (2 bytes)][data (length bytes)]
// Returns the number of payload bytes read, or an error (including net.Error with
// Timeout() == true on deadline expiry, or if the datagram exceeds buffer size).
func ReadUDPFrame(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	if timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, err
	}
	length := int(header[0])<<8 | int(header[1])
	if length == 0 {
		return 0, nil
	}
	if length > len(buf) {
		return 0, fmt.Errorf("ReadUDPFrame: datagram too large: %d > buffer %d", length, len(buf))
	}
	if _, err := io.ReadFull(conn, buf[:length]); err != nil {
		return 0, err
	}
	return length, nil
}
