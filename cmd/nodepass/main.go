// Command nodepass is the unified entry point and CLI dispatcher for the NodePass tunnel.
// It supports two invocation modes:
// 1. Subcommand mode: nodepass <command> [options]
//   - Supports: server, client, master, help, version
//
// 2. URL mode: nodepass <url>
//   - Direct URL specification encodes all tunnel configuration
//
// The application dispatches to the appropriate runtime (client/server/master)
// based on the URL scheme and configuration parameters.
package main

var version = "dev"

func main() { run() }
