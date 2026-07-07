// rate.go implements a token-bucket rate limiter used to cap read and write
// bandwidth on individual connections. It is applied transparently by StatConn.
package transport

import (
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements a token-bucket rate limiter for read and write bandwidth
// control independently. It allows precise per-connection bandwidth limiting with
// token replenishment based on elapsed wall-clock time. Callers block in WaitTokens
// until sufficient tokens are available. The Condition mutex coordinates waiter
// wakeup when tokens are refilled or rates change.
type RateLimiter struct {
	ReadRate, WriteRate     int64      // configured bytes/second for read and write limits
	ReadTokens, WriteTokens int64      // atomic counters for available tokens in each bucket
	LastUpdate              int64      // last refill timestamp in nanoseconds (UnixNano)
	Condition               *sync.Cond // condition variable for waiter coordination
}

// NewRateLimiter creates a token-bucket rate limiter with separate read and write
// limits in bytes/second. Non-positive rates are treated as unlimited (2^40 bytes/s).
// Returns nil if both rates are non-positive, allowing the caller to avoid rate limiting
// checks entirely. Initialize with full token buckets for immediate use.
func NewRateLimiter(readBytesPerSecond, writeBytesPerSecond int64) *RateLimiter {
	if readBytesPerSecond <= 0 && writeBytesPerSecond <= 0 {
		return nil
	}

	if readBytesPerSecond <= 0 {
		readBytesPerSecond = 1 << 40
	}
	if writeBytesPerSecond <= 0 {
		writeBytesPerSecond = 1 << 40
	}

	rl := &RateLimiter{
		ReadRate:  readBytesPerSecond,
		WriteRate: writeBytesPerSecond,
		Condition: sync.NewCond(&sync.Mutex{}),
	}

	atomic.StoreInt64(&rl.ReadTokens, readBytesPerSecond)
	atomic.StoreInt64(&rl.WriteTokens, writeBytesPerSecond)
	atomic.StoreInt64(&rl.LastUpdate, time.Now().UnixNano())

	return rl
}

// WaitRead blocks until the read token bucket has at least bytes tokens, then
// atomically consumes them. This enforces the read rate limit. Returns immediately
// if the RateLimiter is nil or bytes ≤ 0.
func (rl *RateLimiter) WaitRead(bytes int64) {
	if rl == nil || bytes <= 0 {
		return
	}
	rl.WaitTokens(bytes, &rl.ReadTokens)
}

// WaitWrite blocks until the write token bucket has at least bytes tokens, then
// atomically consumes them. This enforces the write rate limit. Returns immediately
// if the RateLimiter is nil or bytes ≤ 0.
func (rl *RateLimiter) WaitWrite(bytes int64) {
	if rl == nil || bytes <= 0 {
		return
	}
	rl.WaitTokens(bytes, &rl.WriteTokens)
}

// SetRate updates the rate limits to the new values and immediately refills both
// token buckets to their new maximums. Broadcasts to wake all blocked waiters so
// they can re-evaluate under the new rates. Useful for dynamic rate adjustment.
// Returns immediately if the RateLimiter is nil.
func (rl *RateLimiter) SetRate(readBytesPerSecond, writeBytesPerSecond int64) {
	if rl == nil {
		return
	}

	if readBytesPerSecond <= 0 {
		readBytesPerSecond = 1 << 40
	}
	if writeBytesPerSecond <= 0 {
		writeBytesPerSecond = 1 << 40
	}

	rl.Condition.L.Lock()
	defer rl.Condition.L.Unlock()

	atomic.StoreInt64(&rl.ReadRate, readBytesPerSecond)
	atomic.StoreInt64(&rl.WriteRate, writeBytesPerSecond)
	atomic.StoreInt64(&rl.ReadTokens, readBytesPerSecond)
	atomic.StoreInt64(&rl.WriteTokens, writeBytesPerSecond)

	rl.Condition.Broadcast()
}

// Reset refills both token buckets to their current rate limits and resets the
// LastUpdate timestamp to now. Broadcasts to wake any blocked waiters. Useful for
// clearing rate limit constraints after a burst or idle period. Returns immediately
// if the RateLimiter is nil.
func (rl *RateLimiter) Reset() {
	if rl == nil {
		return
	}

	rl.Condition.L.Lock()
	defer rl.Condition.L.Unlock()

	readRate := atomic.LoadInt64(&rl.ReadRate)
	writeRate := atomic.LoadInt64(&rl.WriteRate)

	atomic.StoreInt64(&rl.ReadTokens, readRate)
	atomic.StoreInt64(&rl.WriteTokens, writeRate)
	atomic.StoreInt64(&rl.LastUpdate, time.Now().UnixNano())

	rl.Condition.Broadcast()
}

// WaitTokens is the internal method that blocks until the specified token bucket has
// at least bytes tokens. It holds the Condition mutex, refills tokens on each wakeup
// (accounting for elapsed time), and atomically deducts tokens when sufficient.
// Used by WaitRead and WaitWrite. Returns immediately if RateLimiter is nil or bytes ≤ 0.
func (rl *RateLimiter) WaitTokens(bytes int64, tokens *int64) {
	if rl == nil || bytes <= 0 {
		return
	}

	rl.Condition.L.Lock()
	defer rl.Condition.L.Unlock()
	for {
		rl.RefillTokens()

		if curr := atomic.LoadInt64(tokens); curr >= bytes &&
			atomic.CompareAndSwapInt64(tokens, curr, curr-bytes) {
			return
		}
		rl.Condition.Wait()
	}
}

// RefillTokens computes tokens earned based on elapsed wall-clock time since the
// last refill and adds them to both read and write buckets. Each bucket is capped
// at its rate limit (no overflow). Uses atomic CAS on LastUpdate to ensure exactly
// one refill per wall-clock update, preventing double-refilling under contention.
func (rl *RateLimiter) RefillTokens() {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&rl.LastUpdate)

	if elapsed := now - last; elapsed > 0 && atomic.CompareAndSwapInt64(&rl.LastUpdate, last, now) {
		elapsedSeconds := float64(elapsed) / float64(time.Second)
		readAdd := int64(float64(rl.ReadRate) * elapsedSeconds)
		writeAdd := int64(float64(rl.WriteRate) * elapsedSeconds)

		rl.AddTokens(&rl.ReadTokens, readAdd, rl.ReadRate)
		rl.AddTokens(&rl.WriteTokens, writeAdd, rl.WriteRate)

		rl.Condition.Broadcast()
	}
}

// AddTokens atomically adds add tokens to the bucket, capping the result at max.
// Uses a compare-and-swap (CAS) loop to achieve lock-free increment without holding
// the Condition mutex. Returns immediately if add ≤ 0.
func (rl *RateLimiter) AddTokens(tokens *int64, add, max int64) {
	if add <= 0 {
		return
	}
	for {
		curr := atomic.LoadInt64(tokens)
		newVal := min(curr+add, max)
		if atomic.CompareAndSwapInt64(tokens, curr, newVal) {
			break
		}
	}
}
