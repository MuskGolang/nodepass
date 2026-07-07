// stats.go provides Stats, a thread-safe counter struct for tracking TCP/UDP
// traffic bytes and active connection slot counts across the tunnel data paths.
package transport

import "sync/atomic"

// Stats provides real-time traffic statistics and connection slot management for
// a tunnel endpoint. It tracks separate metrics for TCP and UDP, with optional
// slot limiting to cap concurrent connections. All fields are accessed atomically.
type Stats struct {
	TCPRX     uint64 // atomic counter for bytes received over TCP
	TCPTX     uint64 // atomic counter for bytes sent over TCP
	UDPRX     uint64 // atomic counter for bytes received over UDP
	UDPTX     uint64 // atomic counter for bytes sent over UDP
	TCPSlot   int32  // atomic counter of active TCP connections
	UDPSlot   int32  // atomic counter of active UDP sessions
	SlotLimit int32  // maximum total concurrent connections (0 = unlimited)
}

// TryAcquireSlot attempts to reserve a connection slot (TCP or UDP) if the total
// active connections are below SlotLimit. If successful, increments the appropriate
// slot counter and returns true. If the limit is reached, returns false and the
// caller should drop the connection. Returns true if SlotLimit is 0 (unlimited).
func (s *Stats) TryAcquireSlot(isUDP bool) bool {
	if s.SlotLimit == 0 {
		return true
	}

	currentTotal := atomic.LoadInt32(&s.TCPSlot) + atomic.LoadInt32(&s.UDPSlot)
	if currentTotal >= s.SlotLimit {
		return false
	}

	if isUDP {
		atomic.AddInt32(&s.UDPSlot, 1)
	} else {
		atomic.AddInt32(&s.TCPSlot, 1)
	}
	return true
}

// ReleaseSlot releases a previously acquired connection slot (TCP or UDP),
// decrementing the appropriate counter to allow other connections. It is a no-op
// when SlotLimit is 0 (unlimited) or when the counter is already at zero to prevent
// underflow. Must be called for each successful TryAcquireSlot.
func (s *Stats) ReleaseSlot(isUDP bool) {
	if s.SlotLimit == 0 {
		return
	}

	if isUDP {
		if current := atomic.LoadInt32(&s.UDPSlot); current > 0 {
			atomic.AddInt32(&s.UDPSlot, -1)
		}
	} else {
		if current := atomic.LoadInt32(&s.TCPSlot); current > 0 {
			atomic.AddInt32(&s.TCPSlot, -1)
		}
	}
}
