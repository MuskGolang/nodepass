// logger.go provides the levelled, colour-capable logger used throughout
// nodepass. Logger is tightly coupled to Common (every tunnel endpoint
// carries a *Logger).
package common

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"time"
)

// LogLevel is an ordered severity level for log messages, used to filter output at runtime.
// Higher numeric values indicate greater severity; only messages at or above the configured level are output.
type LogLevel int

// Log-level constants in ascending order of severity. Note that None silences all output except where explicitly forced.
const (
	// None suppresses all log output. Useful for disabling logging entirely.
	None LogLevel = iota

	// Debug is the lowest severity level, used for verbose diagnostic output. Includes goroutine lifecycle,
	// connection state changes, buffer allocation/deallocation, and detailed protocol traces.
	Debug

	// Info is the normal operational message level. Includes tunnel lifecycle (handshake start, pool established),
	// successful connections, and normal flow of events. Suitable for production logging.
	Info

	// Warn is used for recoverable problems that don't prevent operation: DNS resolution falls back to cached value,
	// target connection attempt fails but failover to next target succeeds, or protocol detection detects blocked traffic.
	Warn

	// Error is used for non-fatal errors that impact a single connection or session: failed dial, read error on a data connection,
	// or slot limit reached. The tunnel remains active but individual transfers may be dropped.
	Error

	// Event is used for structured CHECK_POINT metric events that are parsed by monitoring systems.
	// Contains timing, throughput, and connection count statistics. Separate from general logging.
	Event
)

// LevelStrings maps each LogLevel constant to its human-readable display label for log output.
var LevelStrings = map[LogLevel]string{
	None:  "NONE",
	Debug: "DEBUG",
	Info:  "INFO",
	Warn:  "WARN",
	Error: "ERROR",
	Event: "EVENT",
}

// ANSI colour codes (SGR - Select Graphic Rendition) used when colour output is enabled.
// These codes work on most Unix/Linux terminals and are wrapped around log level text.
const (
	// AnsiBlue is the ANSI escape code for blue text, used for Debug level messages.
	AnsiBlue = "\033[34m"

	// AnsiGreen is the ANSI escape code for green text, used for Info level messages.
	AnsiGreen = "\033[32m"

	// AnsiYellow is the ANSI escape code for yellow text, used for Warn level messages.
	AnsiYellow = "\033[33m"

	// AnsiRed is the ANSI escape code for red text, used for Error level messages.
	AnsiRed = "\033[31m"

	// AnsiCyan is the ANSI escape code for cyan text, used for Event level messages.
	AnsiCyan = "\033[36m"

	// ResetColor is the ANSI escape code that resets text formatting to default (clears color and style).
	ResetColor = "\033[0m"
)

// LevelColors maps each LogLevel to its corresponding ANSI colour code for colourized terminal output.
// Empty string for None level (no color). Colors are disabled if Logger.ColorEnabled is false.
var LevelColors = map[LogLevel]string{
	None:  "",
	Debug: AnsiBlue,
	Info:  AnsiGreen,
	Warn:  AnsiYellow,
	Error: AnsiRed,
	Event: AnsiCyan,
}

// Logger is the central logging object used throughout nodepass. All methods are safe for concurrent use
// because all modifications to Level and ColorEnabled are guarded by the Mu mutex. Each Common instance
// carries its own Logger, allowing per-tunnel log level and color configuration.
type Logger struct {
	// Mu is the mutex that guards concurrent access to Level, ColorEnabled, and WriteLog.
	// Acquired during level changes and during each log write to serialize output.
	Mu sync.Mutex

	// Level is the minimum LogLevel that will be output. Messages below this level are silently dropped.
	// Can be changed at runtime via SetLogLevel.
	Level LogLevel

	// ColorEnabled controls whether ANSI colour codes are included in log output.
	// Can be toggled at runtime via EnableColor.
	ColorEnabled bool

	// TimeFormat is the Go time layout string used to format log timestamps.
	// Default is "2006-01-02 15:04:05.000" (date + time with millisecond precision).
	TimeFormat string
}

// LogAdapter bridges the Logger to the standard library log.Logger interface,
// allowing third-party libraries that expect *log.Logger to write through the Logger at Debug level.
// Each line is prefixed with "Internal:" to distinguish library-generated logs from application logs.
type LogAdapter struct {
	// logger is the Logger instance that receives adapted log output.
	logger *Logger
}

// StdLogger returns a *log.Logger that writes to this Logger at Debug level using the LogAdapter bridge.
// Useful for third-party libraries that accept a *log.Logger and expect to emit logs independently.
// Output will be prefixed with "Internal:" and filtered by the Logger's minimum level.
func (l *Logger) StdLogger() *log.Logger {
	return log.New(&LogAdapter{logger: l}, "", 0)
}

// Write implements io.Writer for LogAdapter, forwarding stdlib log lines to the Logger at Debug level.
// Trailing whitespace is trimmed before output. Called whenever a third-party library writes to the adapted *log.Logger.
// Returns the number of bytes consumed (always len(p)) and nil error to satisfy io.Writer interface.
func (a *LogAdapter) Write(p []byte) (n int, err error) {
	a.logger.Debug("Internal: %s", string(bytes.TrimSpace(p)))
	return len(p), nil
}

// NewLogger creates a Logger at the given level with optional ANSI colour output. Invalid log levels
// are clamped to Info level for safety. The default time format is "2006-01-02 15:04:05.000"
// (date, time, and milliseconds). All Logger instances start with an unlocked mutex.
func NewLogger(logLevel LogLevel, enableColor bool) *Logger {
	if logLevel < None || logLevel > Event {
		logLevel = Info
	}
	return &Logger{
		Mu:           sync.Mutex{},              // initialize unlocked
		Level:        logLevel,                  // set requested level (clamped if invalid)
		ColorEnabled: enableColor,               // enable/disable ANSI colours
		TimeFormat:   "2006-01-02 15:04:05.000", // ISO date + time with milliseconds
	}
}

// SetLogLevel atomically updates the minimum log level to control verbosity.
// Acquires the mutex to serialize the change. No-op if the new level equals the current level.
// Safe to call concurrently with log operations.
func (l *Logger) SetLogLevel(logLevel LogLevel) {
	if l.Level != logLevel {
		l.Mu.Lock()
		defer l.Mu.Unlock()
		l.Level = logLevel
	}
}

// GetLogLevel returns the current minimum log level. Acquires the mutex to read consistently
// and returns the snapshot value. Safe to call concurrently with SetLogLevel and log operations.
func (l *Logger) GetLogLevel() LogLevel {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	return l.Level
}

// EnableColor toggles ANSI colour output on/off. Acquires the mutex to serialize the change.
// No-op if the new state matches the current ColorEnabled value.
// Safe to call concurrently with log operations.
func (l *Logger) EnableColor(enable bool) {
	if l.ColorEnabled != enable {
		l.Mu.Lock()
		defer l.Mu.Unlock()
		l.ColorEnabled = enable
	}
}

// DoLog emits a message at the given level. Messages below the Logger's minimum level are silently dropped.
// Invalid log levels are clamped to Info. All output is serialized through the mutex to prevent interleaved writes.
// The message is formatted using fmt.Sprintf before being passed to WriteLog.
// This is the central logging function; convenience methods (Debug, Info, Warn, Error, Event) call this with their specific level.
func (l *Logger) DoLog(logLevel LogLevel, format string, v ...any) {
	if logLevel < None || logLevel > Event {
		logLevel = Info // clamp invalid levels to Info
	}
	if l.Level == None {
		return // all output suppressed
	}
	if logLevel < l.Level {
		return // message below configured level; drop silently
	}

	timestamp := time.Now().Format(l.TimeFormat) // format current time
	levelStr := LevelStrings[logLevel]           // look up level label
	message := fmt.Sprintf(format, v...)         // format message with args

	l.Mu.Lock() // serialize output
	defer l.Mu.Unlock()
	l.WriteLog(logLevel, timestamp, levelStr, message)
}

// WriteLog is the low-level write path called after the mutex is acquired and level filtering is complete.
// It formats and prints the log line to stdout with optional ANSI colour codes around the level label.
// Format with color: "TIMESTAMP  <COLOR>LEVEL<RESET>  MESSAGE"
// Format without color: "TIMESTAMP  LEVEL  MESSAGE"
// Must be called with the mutex held to prevent concurrent output corruption.
func (l *Logger) WriteLog(level LogLevel, timestamp, levelStr, message string) {
	if l.ColorEnabled {
		colorCode := LevelColors[level]
		fmt.Printf("%s  %s%s%s  %s\n", timestamp, colorCode, levelStr, ResetColor, message)
	} else {
		fmt.Printf("%s  %s  %s\n", timestamp, levelStr, message)
	}
}

// Debug logs a message at Debug level. Calls DoLog with Debug level; dropped if Logger.Level > Debug.
// Used for verbose diagnostic output: goroutine lifecycle, connection state changes, buffer operations, protocol traces.
func (l *Logger) Debug(format string, v ...any) {
	l.DoLog(Debug, format, v...)
}

// Info logs a message at Info level. Calls DoLog with Info level; dropped if Logger.Level > Info.
// Used for normal operational messages: tunnel lifecycle, successful connections, normal flow events.
func (l *Logger) Info(format string, v ...any) {
	l.DoLog(Info, format, v...)
}

// Warn logs a message at Warn level. Calls DoLog with Warn level; dropped if Logger.Level > Warn.
// Used for recoverable problems: DNS fallback, connection retry success, detected blocked traffic, non-fatal issues.
func (l *Logger) Warn(format string, v ...any) {
	l.DoLog(Warn, format, v...)
}

// Error logs a message at Error level. Calls DoLog with Error level; dropped if Logger.Level > Error.
// Used for non-fatal errors: failed dial, read error on connection, slot limit reached, transfer interrupted.
func (l *Logger) Error(format string, v ...any) {
	l.DoLog(Error, format, v...)
}

// Event logs a message at Event level, typically used for structured CHECK_POINT metric lines.
// Calls DoLog with Event level; Event level is the highest severity and is typically never filtered.
// Format: "CHECK_POINT|KEY1=VALUE1|KEY2=VALUE2|..." for machine parsing and metrics extraction.
func (l *Logger) Event(format string, v ...any) {
	l.DoLog(Event, format, v...)
}
