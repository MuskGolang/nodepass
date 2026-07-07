// run.go is the application entry point. It parses the command line, builds a
// logger, creates the appropriate tunnel runtime (client/server/master), and
// calls Run(). Build version is set via -ldflags "-X main.version=<ver>".
package main

import (
	"fmt"
	"net/url"
	"os"
	"runtime"

	"github.com/NodePassProject/nodepass/internal/client"
	"github.com/NodePassProject/nodepass/internal/common"
	"github.com/NodePassProject/nodepass/internal/master"
	"github.com/NodePassProject/nodepass/internal/server"
)

// run is the main execution function that orchestrates application startup.
// It delegates to start() and handles any errors via exit().
func run() {
	if err := start(os.Args); err != nil {
		exit(err)
	}
}

// start is the main application initialization function. It performs the following:
// 1. Parses command-line arguments into a configuration URL
// 2. Initializes the logger with the specified log level
// 3. Creates the appropriate core instance (server, client, or master) based on URL scheme
// 4. Calls Run() on the core to start the tunnel
//
// Returns an error if any step fails; otherwise, blocks until the tunnel shuts down.
func start(args []string) error {
	parsedURL, err := newCommandLine(args).parse()
	if err != nil {
		return fmt.Errorf("start: parse command failed: %w", err)
	}

	logger := initLogger(parsedURL.Query().Get("log"))

	core, err := createCore(parsedURL, logger)
	if err != nil {
		return fmt.Errorf("start: create core failed: %w", err)
	}

	core.Run()
	return nil
}

// exit prints an error message to stderr and terminates the application with exit code 1.
// The message includes version, OS, architecture, PID, and error details for debugging.
// Prints "none" as the error message if err is nil.
func exit(err error) {
	errMsg := "none"
	if err != nil {
		errMsg = err.Error()
	}
	fmt.Fprintf(os.Stderr,
		"nodepass-%s %s/%s pid=%d error=%s\n\nrun 'nodepass --help' for usage\n",
		version, runtime.GOOS, runtime.GOARCH, os.Getpid(), errMsg)

	os.Exit(1)
}

// initLogger creates and configures a Logger with the specified log level string.
// Supported levels: "none" (no logging), "debug" (verbose), "warn" (warnings only),
// "error" (errors only), "event" (significant events). Defaults to Info level.
// Logs the level change after initialization (except for "none").
func initLogger(level string) *common.Logger {
	logger := common.NewLogger(common.Info, true)
	switch level {
	case "none":
		logger.SetLogLevel(common.None)
	case "debug":
		logger.SetLogLevel(common.Debug)
		logger.Debug("Init log level: DEBUG")
	case "warn":
		logger.SetLogLevel(common.Warn)
		logger.Warn("Init log level: WARN")
	case "error":
		logger.SetLogLevel(common.Error)
		logger.Error("Init log level: ERROR")
	case "event":
		logger.SetLogLevel(common.Event)
		logger.Event("Init log level: EVENT")
	default:
	}
	return logger
}

// createCore creates the appropriate tunnel runtime instance based on the URL scheme.
// Dispatches to the correct constructor (NewServer, NewClient, or NewMaster) and
// passes the TLS configuration and logger. Returns the core instance or an error
// if the scheme is unrecognized. The returned instance implements Run() for startup.
func createCore(parsedURL *url.URL, logger *common.Logger) (interface{ Run() }, error) {
	tlsCode, tlsConfig := getTLSProtocol(parsedURL, logger)
	switch parsedURL.Scheme {
	case "server":
		return server.NewServer(parsedURL, tlsCode, tlsConfig, logger)
	case "client":
		return client.NewClient(parsedURL, tlsConfig, logger)
	case "master":
		return master.NewMaster(parsedURL, tlsCode, tlsConfig, logger, version)
	default:
		return nil, fmt.Errorf("createCore: unknown core: %v", parsedURL)
	}
}
