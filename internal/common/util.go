// util.go provides small, self-contained utility functions:
// environment variable helpers and a generic channel drainer.
package common

import (
	"os"
	"strconv"
	"time"
)

// GetEnvAsInt reads an integer from the named environment variable and returns it.
// Returns defaultValue when the variable is absent, non-numeric, or has a negative value.
// Used by the initialization code to load environment-tunable runtime parameters (NP_* variables).
func GetEnvAsInt(name string, defaultValue int) int {
	if valueStr, exists := os.LookupEnv(name); exists {
		if value, err := strconv.Atoi(valueStr); err == nil && value >= 0 {
			return value // successfully parsed and non-negative
		}
	}
	return defaultValue // fallback to default
}

// GetEnvAsDuration reads a time.Duration from the named environment variable and returns it.
// Returns defaultValue when the variable is absent, unparseable, or has a negative value.
// Accepts Go duration format strings (e.g., "5s", "100ms", "1h").
// Used by the initialization code to load environment-tunable timeout and interval parameters (NP_* variables).
func GetEnvAsDuration(name string, defaultValue time.Duration) time.Duration {
	if valueStr, exists := os.LookupEnv(name); exists {
		if value, err := time.ParseDuration(valueStr); err == nil && value >= 0 {
			return value // successfully parsed and non-negative
		}
	}
	return defaultValue // fallback to default
}

// Drain empties a channel by consuming all buffered values without blocking.
// Non-blocking drain using select{case <-ch: default: return}. Used during Stop() to
// release any goroutines waiting on full channels (SignalChan, WriteChan, VerifyChan)
// so that they can be garbage collected.
func Drain[T any](ch <-chan T) {
	for {
		select {
		case <-ch:
			// consumed a value; try again
		default:
			// channel is empty (or closed)
			return
		}
	}
}
