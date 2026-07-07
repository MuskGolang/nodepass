// cli.go parses the command line into a *url.URL that encodes the full tunnel
// configuration. Flags are assembled into URL components: scheme (server/client/
// master), userinfo (password), host (tunnel address), path (target address),
// and query parameters (all optional tunables).
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// commandLine represents the complete CLI configuration with all parsed flags
// for different operation modes (server, client, master). It consolidates all
// flag pointers and provides methods to parse CLI arguments and build a URL.
type commandLine struct {
	args       []string // raw command-line arguments from os.Args
	password   *string  // connection password for authentication
	tunnelAddr *string  // tunnel listening/server address (e.g., 0.0.0.0 or server.com)
	tunnelPort *string  // tunnel listening/server port
	targetAddr *string  // target backend address to forward traffic to
	targetPort *string  // target backend port
	targets    *string  // multiple targets in comma-separated format
	log        *string  // log level (none, debug, warn, error, event)
	dns        *string  // DNS cache TTL in seconds
	sni        *string  // SNI (Server Name Indication) hostname for TLS
	lbs        *string  // load balancing strategy (rr, random, etc.)
	min        *string  // minimum pool capacity for clients
	max        *string  // maximum pool capacity
	mode       *string  // run mode (0=auto, 1=single, 2=tunnel)
	pool       *string  // pool backend (0=TCP, 1=QUIC, 2=WebSocket, 3=HTTP/2)
	tls        *string  // TLS mode (0=none, 1=self-signed RAM, 2=file-based)
	crt        *string  // certificate file path for TLS mode 2
	key        *string  // private key file path for TLS mode 2
	dial       *string  // outbound dialer IP for source binding
	read       *string  // read timeout in seconds
	rate       *string  // bandwidth rate limit in Mbps
	slot       *string  // maximum concurrent connection slots
	proxy      *string  // enable PROXY protocol v1 (true/false)
	block      *string  // application protocols to block (1=SOCKS, 2=HTTP, 3=TLS)
	notcp      *string  // disable TCP support (true/false)
	noudp      *string  // disable UDP support (true/false)
}

// newCommandLine creates a new commandLine instance initialized with raw command-line arguments.
// The args slice typically comes from os.Args. Call parse() to parse the arguments.
func newCommandLine(args []string) *commandLine {
	return &commandLine{args: args}
}

// parse parses the command-line arguments and returns a *url.URL representing
// the complete tunnel configuration. It supports two input formats:
// 1. Command mode: nodepass <command> [--flag value ...]
//   - Parses flags and constructs URL from components
//
// 2. URL mode: nodepass <url>
//   - Directly parses and returns the URL
//
// Returns an error if parsing fails or the command is unrecognized.
func (c *commandLine) parse() (*url.URL, error) {
	if len(c.args) == 2 && strings.Contains(c.args[1], "://") {
		return url.Parse(c.args[1])
	}

	if len(c.args) < 2 {
		return nil, fmt.Errorf("usage: nodepass <command> [options] or nodepass <url>")
	}

	command := c.args[1]
	cmdArgs := c.args[2:]

	switch command {
	case "server":
		return c.parseServerCommand(cmdArgs)
	case "client":
		return c.parseClientCommand(cmdArgs)
	case "master":
		return c.parseMasterCommand(cmdArgs)
	case "help", "-h", "--help":
		c.printHelp()
		os.Exit(0)
	case "version", "-v", "--version":
		fmt.Printf("nodepass-%s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	default:
		fullArg := strings.Join(c.args[1:], " ")
		if strings.Contains(fullArg, "://") {
			return url.Parse(fullArg)
		}
		return nil, fmt.Errorf("unknown command: %s", command)
	}

	return nil, nil
}

// addServerFlags registers all command-line flags for the server command.
// The server listens for incoming tunnel connections and forwards traffic to target(s).
// Flags are organized by category:
//   - Authentication: password (shared secret for client verification)
//   - Tunnel: tunnel-addr (listen address), tunnel-port (listen port)
//   - Target: target-addr/target-port (single backend), targets (multiple backends)
//   - TLS: tls (mode: 0/1/2), crt (cert file), key (key file)
//   - Pooling: max (pool capacity), lbs (load balance strategy), pool (transport backend)
//   - Tuning: mode (0=auto/1=single/2=tunnel), dial (source IP), read (timeout), rate (Mbps limit), slot (concurrent limit)
//   - Protocol: proxy (PROXY v1 support), block (SOCKS/HTTP/TLS filtering), notcp (disable TCP), noudp (disable UDP)
func (c *commandLine) addServerFlags(fs *flag.FlagSet) {
	c.password = fs.String("password", "", "Connection password for client authentication")
	c.tunnelAddr = fs.String("tunnel-addr", "", "Server tunnel listening address (e.g., 0.0.0.0)")
	c.tunnelPort = fs.String("tunnel-port", "", "Server tunnel listening port number")
	c.targetAddr = fs.String("target-addr", "", "Backend target address for single target")
	c.targetPort = fs.String("target-port", "", "Backend target port for single target")
	c.targets = fs.String("targets", "", "Multiple targets in comma-separated format (overrides single target)")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.dns = fs.String("dns", "", "DNS cache TTL in seconds (0=disabled)")
	c.tls = fs.String("tls", "", "TLS mode: 0=none, 1=self-signed RAM cert, 2=file-based cert")
	c.crt = fs.String("crt", "", "Certificate file path (for tls=2, X509 PEM format)")
	c.key = fs.String("key", "", "Private key file path (for tls=2, PEM format)")
	c.lbs = fs.String("lbs", "", "Load balancing strategy: rr (round-robin), random (default: rr)")
	c.max = fs.String("max", "", "Maximum pool capacity for incoming client connections")
	c.mode = fs.String("mode", "", "Run mode: 0=auto (try single then tunnel), 1=single-connection, 2=tunnel pool")
	c.pool = fs.String("pool", "", "Connection pool type: 0=TCP, 1=QUIC, 2=WebSocket, 3=HTTP/2")
	c.dial = fs.String("dial", "", "Outbound source IP for dialing backends (bind to specific interface)")
	c.read = fs.String("read", "", "Read timeout in seconds for idle connections (0=disabled)")
	c.rate = fs.String("rate", "", "Bandwidth rate limit in Mbps (per-connection, 0=unlimited)")
	c.slot = fs.String("slot", "", "Maximum concurrent connection slots (0=unlimited)")
	c.proxy = fs.String("proxy", "", "Enable PROXY protocol v1 support (true/false)")
	c.block = fs.String("block", "", "Block application protocols: 1=SOCKS4/5, 2=HTTP, 3=TLS ClientHello")
	c.notcp = fs.String("notcp", "", "Disable TCP protocol support (true/false)")
	c.noudp = fs.String("noudp", "", "Disable UDP protocol support (true/false)")
}

// addClientFlags registers all command-line flags for the client command.
// The client connects outbound to a server and forwards incoming traffic to local target(s).
// Flags are organized by category:
//   - Authentication: password (shared secret matching server)
//   - Tunnel: tunnel-addr (server hostname/IP), tunnel-port (server port)
//   - Target: target-addr/target-port (local backend), targets (multiple backends)
//   - TLS: tls (mode: 0/1/2), crt (client cert), key (client key), sni (server name for verification)
//   - Pooling: min/max (capacity bounds), lbs (load balance strategy)
//   - Tuning: mode (0=auto/1=single/2=tunnel), dial (source IP), read (timeout), rate (Mbps limit), slot (concurrent limit)
//   - Protocol: proxy (PROXY v1 support), block (SOCKS/HTTP/TLS filtering), notcp (disable TCP), noudp (disable UDP)
func (c *commandLine) addClientFlags(fs *flag.FlagSet) {
	c.password = fs.String("password", "", "Connection password (must match server)")
	c.tunnelAddr = fs.String("tunnel-addr", "", "Server tunnel address (hostname or IP)")
	c.tunnelPort = fs.String("tunnel-port", "", "Server tunnel port number")
	c.targetAddr = fs.String("target-addr", "", "Local target address for forwarding")
	c.targetPort = fs.String("target-port", "", "Local target port for single target")
	c.targets = fs.String("targets", "", "Multiple local targets in comma-separated format")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.dns = fs.String("dns", "", "DNS cache TTL in seconds (0=disabled)")
	c.sni = fs.String("sni", "", "SNI (Server Name Indication) for TLS certificate verification")
	c.tls = fs.String("tls", "", "TLS mode: 0=none, 1=insecure skip verify, 2=verify with SNI")
	c.crt = fs.String("crt", "", "Client certificate file path (for mutual TLS, PEM format)")
	c.key = fs.String("key", "", "Client private key file path (for mutual TLS, PEM format)")
	c.lbs = fs.String("lbs", "", "Load balancing strategy: rr (round-robin), random (default: rr)")
	c.min = fs.String("min", "", "Minimum pool capacity (adaptive lower bound)")
	c.mode = fs.String("mode", "", "Connection mode: 0=auto, 1=single-connection, 2=tunnel pool")
	c.dial = fs.String("dial", "", "Outbound source IP for connecting to server (bind to specific interface)")
	c.read = fs.String("read", "", "Read timeout in seconds for idle connections (0=disabled)")
	c.rate = fs.String("rate", "", "Bandwidth rate limit in Mbps (per-connection, 0=unlimited)")
	c.slot = fs.String("slot", "", "Maximum concurrent connection slots (0=unlimited)")
	c.proxy = fs.String("proxy", "", "Enable PROXY protocol v1 support (true/false)")
	c.block = fs.String("block", "", "Block application protocols: 1=SOCKS4/5, 2=HTTP, 3=TLS ClientHello")
	c.notcp = fs.String("notcp", "", "Disable TCP protocol support (true/false)")
	c.noudp = fs.String("noudp", "", "Disable UDP protocol support (true/false)")
}

// addMasterFlags registers all command-line flags for the master (control API) command.
// The master provides a REST/OpenAPI control interface for managing tunnels and querying stats.
// Flags are minimal and focused on API server configuration:
//   - Listening: tunnel-addr (API address), tunnel-port (API port)
//   - TLS: tls (mode: 0/1/2), crt (cert file), key (key file) for securing the API
//   - Logging: log (verbosity level)
func (c *commandLine) addMasterFlags(fs *flag.FlagSet) {
	c.tunnelAddr = fs.String("tunnel-addr", "", "Master API listening address (e.g., 0.0.0.0, localhost)")
	c.tunnelPort = fs.String("tunnel-port", "", "Master API listening port number")
	c.log = fs.String("log", "", "Log level: none, debug, warn, error, event")
	c.tls = fs.String("tls", "", "TLS mode: 0=none (plain HTTP), 1=self-signed RAM cert, 2=file-based cert")
	c.crt = fs.String("crt", "", "Certificate file path for API server (for tls=2, X509 PEM format)")
	c.key = fs.String("key", "", "Private key file path for API server (for tls=2, PEM format)")
}

// buildQuery constructs the URL query string containing all non-empty parsed flags.
// Only parameters with values are included to keep URLs clean. This encodes all
// optional tunables: logging, DNS, TLS config, pool sizing, rate limiting,
// protocol filtering, and other behavior-controlling parameters.
// Note: cert/key are only included if tls=2 (file-based mode).
func (c *commandLine) buildQuery() url.Values {
	query := url.Values{}

	if c.log != nil && *c.log != "" {
		query.Set("log", *c.log)
	}
	if c.dns != nil && *c.dns != "" {
		query.Set("dns", *c.dns)
	}
	if c.sni != nil && *c.sni != "" {
		query.Set("sni", *c.sni)
	}
	if c.lbs != nil && *c.lbs != "" {
		query.Set("lbs", *c.lbs)
	}
	if c.min != nil && *c.min != "" {
		query.Set("min", *c.min)
	}
	if c.max != nil && *c.max != "" {
		query.Set("max", *c.max)
	}
	if c.mode != nil && *c.mode != "" {
		query.Set("mode", *c.mode)
	}
	if c.pool != nil && *c.pool != "" {
		query.Set("type", *c.pool)
	}
	if c.tls != nil && *c.tls != "" {
		query.Set("tls", *c.tls)
	}
	if c.crt != nil && c.key != nil && c.tls != nil && *c.tls == "2" {
		if *c.crt != "" {
			query.Set("crt", *c.crt)
		}
		if *c.key != "" {
			query.Set("key", *c.key)
		}
	}
	if c.dial != nil && *c.dial != "" {
		query.Set("dial", *c.dial)
	}
	if c.read != nil && *c.read != "" {
		query.Set("read", *c.read)
	}
	if c.rate != nil && *c.rate != "" {
		query.Set("rate", *c.rate)
	}
	if c.slot != nil && *c.slot != "" {
		query.Set("slot", *c.slot)
	}
	if c.proxy != nil && *c.proxy != "" {
		query.Set("proxy", *c.proxy)
	}
	if c.block != nil && *c.block != "" {
		query.Set("block", *c.block)
	}
	if c.notcp != nil && *c.notcp != "" {
		query.Set("notcp", *c.notcp)
	}
	if c.noudp != nil && *c.noudp != "" {
		query.Set("noudp", *c.noudp)
	}

	return query
}

// buildHost constructs the URL host component (address:port) from tunnel-addr and tunnel-port flags.
// The host represents where the tunnel listens (server) or connects to (client).
// Format: "address:port", "address" (port only), ":port" (port only), or "" (both unset).
// Returns empty string if neither flag is provided.
func (c *commandLine) buildHost() string {
	addr := ""
	if c.tunnelAddr != nil && *c.tunnelAddr != "" {
		addr = *c.tunnelAddr
	}
	if c.tunnelPort != nil && *c.tunnelPort != "" {
		if addr != "" {
			return fmt.Sprintf("%s:%s", addr, *c.tunnelPort)
		}
		return ":" + *c.tunnelPort
	}
	return addr
}

// buildPath constructs the URL path component encoding the target backend address(es).
// Prioritizes the targets field (multiple backends in CSV) over single target-addr/target-port.
// The path represents the final destination for tunneled traffic (e.g., /127.0.0.1:8080 or /backend1,backend2).
// Format: "/address:port", "/address", "/:port", or "/" (no target).
// Returns "/" if no target is specified (default).
func (c *commandLine) buildPath() string {
	if c.targets != nil && *c.targets != "" {
		return "/" + *c.targets
	}
	addr := ""
	if c.targetAddr != nil && *c.targetAddr != "" {
		addr = *c.targetAddr
	}
	if c.targetPort != nil && *c.targetPort != "" {
		if addr != "" {
			return fmt.Sprintf("/%s:%s", addr, *c.targetPort)
		}
		return "/:" + *c.targetPort
	}
	if addr != "" {
		return "/" + addr
	}
	return "/"
}

// buildUserInfo constructs the URL userinfo from the password flag.
// The password is used as a shared secret for authentication between client and server.
// In URLs, it appears as "scheme://password@host/path" but is not conventionally a username.
// Returns nil if no password is provided, allowing unauthenticated mode.
func (c *commandLine) buildUserInfo() *url.Userinfo {
	if c.password != nil && *c.password != "" {
		return url.User(*c.password)
	}
	return nil
}

// parseServerCommand parses the "nodepass server" command flags and constructs a configuration URL.
// It registers all server-specific flags, parses them from args, then builds a URL with:
//   - Scheme: "server" to identify this as a server configuration
//   - User: password (authentication secret)
//   - Host: tunnel listening address and port
//   - Path: target backend address(es)
//   - Query: all optional tuning parameters (TLS, pooling, rate limiting, etc.)
//
// Returns an error if flag parsing fails.
func (c *commandLine) parseServerCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	c.addServerFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass server [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "server",
		User:     c.buildUserInfo(),
		Host:     c.buildHost(),
		Path:     c.buildPath(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

// parseClientCommand parses the "nodepass client" command flags and constructs a configuration URL.
// It registers all client-specific flags, parses them from args, then builds a URL with:
//   - Scheme: "client" to identify this as a client configuration
//   - User: password (must match server)
//   - Host: remote server address and port to connect to
//   - Path: local target backend address(es) to forward traffic to
//   - Query: all optional tuning parameters (TLS, SNI, pool sizing, rate limiting, etc.)
//
// Returns an error if flag parsing fails.
func (c *commandLine) parseClientCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	c.addClientFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass client [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "client",
		User:     c.buildUserInfo(),
		Host:     c.buildHost(),
		Path:     c.buildPath(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

// parseMasterCommand parses the "nodepass master" command flags and constructs a configuration URL.
// It registers all master-specific flags, parses them from args, then builds a URL with:
//   - Scheme: "master" to identify this as a control API server configuration
//   - User: unused (no password for master API)
//   - Host: API listening address and port
//   - Path: unused (no path routing for API)
//   - Query: logging and TLS configuration parameters
//
// The master provides REST/OpenAPI endpoints for managing and monitoring tunnels.
// Returns an error if flag parsing fails.
func (c *commandLine) parseMasterCommand(args []string) (*url.URL, error) {
	fs := flag.NewFlagSet("master", flag.ExitOnError)
	c.addMasterFlags(fs)

	fs.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: nodepass master [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &url.URL{
		Scheme:   "master",
		Host:     c.buildHost(),
		RawQuery: c.buildQuery().Encode(),
	}, nil
}

// printHelp prints the comprehensive help message showing usage, commands, and examples to stdout.
func (c *commandLine) printHelp() {
	fmt.Fprintf(os.Stdout, `NodePass

Usage:
  nodepass <command> [options]
  nodepass <url>

Commands:
  server    Start a NodePass server
  client    Start a NodePass client
  master    Start a NodePass master
  help      Show this helper message
  version   Show version information

`)
}
