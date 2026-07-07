# NodePass MCP Reference

## Overview

NodePass Master Mode exposes a Model Context Protocol (MCP) compatible management endpoint over HTTP JSON-RPC 2.0. MCP clients can use this endpoint to discover tools and manage NodePass instances through the same master process that provides the REST API.

The MCP implementation is intended for automation and AI-assisted operations. It can list and inspect instances, create new client or server instances, change instance configuration, control lifecycle state, export or import instance configuration, run TCP connectivity checks, and read or update master metadata.

## Endpoint

MCP is available only in Master Mode.

```bash
nodepass "master://0.0.0.0:9090?log=info"
```

The MCP path is derived from the master API prefix:

| Master URL path | REST base path | MCP endpoint |
|-----------------|----------------|--------------|
| empty or `/`    | `/api/v1`      | `/api/v2`   |
| `/admin`        | `/admin/v1`    | `/admin/v2` |

For the default master URL above, the MCP endpoint is:

```text
http://127.0.0.1:9090/api/v2
```

If TLS is enabled for the master, use `https://` with the same path.

## Authentication

The MCP endpoint is protected by the same API key middleware as the protected REST endpoints. Include the API key in every request:

```http
X-API-Key: <api-key>
```

The key is generated on first master startup, printed to stdout, and persisted in the master state file. Missing or invalid API keys return HTTP `401` before JSON-RPC handling.

## Transport And Request Format

NodePass accepts HTTP `POST` requests with a JSON-RPC 2.0 body:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

Headers:

```http
Content-Type: application/json
X-API-Key: <api-key>
```

Only `POST` is accepted. Other methods return HTTP `405`.

Successful JSON-RPC responses use HTTP `200` and contain `result`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {}
}
```

JSON-RPC errors also use HTTP `200` and contain `error`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": "id is required"
  }
}
```

HTTP authentication and method errors are returned before JSON-RPC processing.

## Supported JSON-RPC Methods

| Method | Description |
|--------|-------------|
| `initialize` | Returns the advertised MCP protocol version, server information, and capabilities. |
| `tools/list` | Returns all available MCP tools with JSON schemas. |
| `tools/call` | Executes a tool. Tool arguments are provided in `params.arguments`. |

### initialize

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {}
}
```

Response fields:

| Field | Description |
|-------|-------------|
| `protocolVersion` | MCP protocol version advertised by NodePass. In this codebase the value is `2025-11-25`. |
| `capabilities.tools` | Tool capability declaration. |
| `serverInfo.name` | Server name, currently `Master`. |
| `serverInfo.version` | NodePass binary version. |

### tools/list

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

The response contains a `tools` array. Each item has:

| Field | Description |
|-------|-------------|
| `name` | Tool name used in `tools/call`. |
| `description` | Human-readable tool description. |
| `inputSchema` | JSON schema for accepted arguments. |

### tools/call

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "list_instances",
    "arguments": {}
  }
}
```

Most tool responses include a `content` array with text for MCP clients, plus structured fields such as `instance`, `instances`, `config`, `result`, or `info`.

## Tool Summary

| Tool | Purpose |
|------|---------|
| `list_instances` | List all managed instances except the internal API key record. |
| `get_instance` | Get one instance by ID. |
| `create_instance` | Create and start a client or server instance from structured arguments. |
| `update_instance` | Update metadata such as alias, restart policy, peer, and tags. |
| `control_instance` | Start, stop, restart, or reset traffic counters. |
| `set_instance_basic` | Update instance type, tunnel endpoint, target endpoint, targets, or log level. |
| `set_instance_security` | Update password, TLS mode, certificate paths, or SNI. |
| `set_instance_connection` | Update mode and connection pool settings. |
| `set_instance_network` | Update DNS, source IP, read timeout, bandwidth limit, or slot limit. |
| `set_instance_protocol` | Update TCP/UDP switches and PROXY protocol behavior. |
| `set_instance_traffic` | Update protocol blocking and load balancing. |
| `set_instance_advanced` | Update arbitrary URL query parameters. |
| `get_instance_config` | Return a parsed, structured version of an instance config URL. |
| `delete_instance` | Stop and remove an instance. |
| `export_instances` | Export instances to `nodepass.json`. |
| `import_instances` | Import instances from `nodepass.json`. |
| `tcping_target` | Test TCP connectivity to `host:port`. |
| `get_master_info` | Return master and system information. |
| `update_master_info` | Update the master alias. |

## Common Arguments

Most instance configuration arguments are strings because they map directly to NodePass URL components or query parameters.

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. Generated as an 8-character hexadecimal string. |
| `alias` | Human-readable instance alias. |
| `type` | Instance type: `server` or `client`. |
| `tunnel_address` | Tunnel bind address for a server, or remote server address for a client. |
| `tunnel_port` | Tunnel port. |
| `target_address` | Target host address. |
| `target_port` | Target port. |
| `targets` | Multiple targets in URL path form, for example `host1:80,host2:80`. Takes precedence over `target_address` and `target_port`. |
| `password` | URL userinfo password used in the instance URL. |
| `log` | Log level: `none`, `debug`, `info`, `warn`, `error`, or `event`. |
| `tls` | TLS mode: `0` none, `1` self-signed, `2` custom certificate. |
| `crt` | Certificate file path when `tls=2`. |
| `key` | Private key file path when `tls=2`. |
| `sni` | SNI hostname, mainly for client dual-end mode. |
| `dns` | DNS cache TTL, for example `5m` or `1h`. |
| `lbs` | Load balancing strategy. Current MCP schema exposes `0`, `1`, and `2`. |
| `mode` | Runtime mode: `0` auto, `1` reverse or single-end, `2` forward or dual-end. |
| `min` | Minimum pool size. Usually used by client dual-end mode. |
| `max` | Maximum pool size. Usually used by server or dual-end mode. |
| `pool` | Connection pool backend: `0` TCP, `1` QUIC, `2` WebSocket, `3` HTTP/2. Internally this maps to the URL query parameter `type`. |
| `dial` | Source IP for outbound connections. Defaults to `auto` when not provided in the full generated config. |
| `read` | Read timeout, for example `30s`, `5m`, or `1h`. |
| `rate` | Bandwidth limit in Mbps. `0` means unlimited. |
| `slot` | Maximum concurrent connection slots. `0` means unlimited. |
| `proxy` | PROXY protocol v1: `0` disabled, `1` enabled. |
| `block` | Protocol blocking flags: `1` SOCKS, `2` HTTP, `3` TLS. Values may be combined, for example `123`. |
| `notcp` | TCP switch: `0` enabled, `1` disabled. |
| `noudp` | UDP switch: `0` enabled, `1` disabled. |

## Instance Tools

### list_instances

Arguments: none.

Returns:

| Field | Description |
|-------|-------------|
| `content` | Text summary such as `Found 2 instances`. |
| `instances` | Array of instance objects. |

### get_instance

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Returns one `instance` object.

### create_instance

Creates an instance from structured fields, stores it in master state, and starts it asynchronously.

Required arguments:

| Argument | Description |
|----------|-------------|
| `type` | `server` or `client`. |
| `tunnel_port` | Tunnel port. |
| `target_port` | Target port, unless `targets` fully supplies the target path. |

Optional arguments:

`alias`, `tunnel_address`, `target_address`, `targets`, `password`, `log`, `tls`, `crt`, `key`, `sni`, `dns`, `lbs`, `mode`, `min`, `max`, `pool`, `dial`, `read`, `rate`, `slot`, `proxy`, `block`, `notcp`, `noudp`.

Behavior:

- Generates an 8-character instance ID.
- Builds a `server://` or `client://` URL.
- Applies provided URL query parameters.
- Maps the MCP `pool` argument to the URL query parameter `type`.
- Enhances the URL with master defaults such as log level, server TLS settings, and default server pool type when applicable.
- Stores the instance with `restart: true`.
- Starts the instance asynchronously.
- Sends an SSE `create` event.

Example:

```json
{
  "jsonrpc": "2.0",
  "id": 10,
  "method": "tools/call",
  "params": {
    "name": "create_instance",
    "arguments": {
      "alias": "web-tunnel",
      "type": "server",
      "tunnel_address": "0.0.0.0",
      "tunnel_port": "10101",
      "target_address": "127.0.0.1",
      "target_port": "3000",
      "log": "info",
      "pool": "0"
    }
  }
}
```

### update_instance

Updates instance metadata. It does not change the tunnel URL.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

| Argument | Type | Description |
|----------|------|-------------|
| `alias` | string | Updates the alias when non-empty. |
| `restart` | boolean | Controls auto-start on master state load. |
| `peer` | object | Optional peer metadata with `sid`, `type`, and `alias`. |
| `tags` | object | Replaces the instance tag map. Values are converted to strings. |

Limits:

- `alias`, peer fields, tag keys, and tag values must not exceed 256 characters.
- The internal API key record ID `********` cannot be updated.

### control_instance

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |
| `action` | One of `start`, `stop`, `restart`, or `reset`. |

Behavior:

- `start` starts the instance only if it is currently stopped.
- `stop` stops the instance when it is not already stopped.
- `restart` stops the instance, waits briefly, and starts it again.
- `reset` sets TCP and UDP traffic counters to zero and persists the updated state.

The internal API key record ID `********` cannot be controlled.

### set_instance_basic

Updates URL basics and restarts the instance with the new URL.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`type`, `tunnel_address`, `tunnel_port`, `target_address`, `target_port`, `targets`, `log`.

At least one update must be provided. `type` must be `client` or `server`.

### set_instance_security

Updates security-related URL values and restarts the instance.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`password`, `tls`, `crt`, `key`, `sni`.

Empty `password`, `crt`, `key`, or `sni` values clear those fields. `tls` is updated only when non-empty.

### set_instance_connection

Updates connection mode and pool settings, then restarts the instance.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`mode`, `min`, `max`, `pool`.

`pool` maps to the URL query parameter `type`.

### set_instance_network

Updates network tuning values, then restarts the instance.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`dns`, `dial`, `read`, `rate`, `slot`.

Empty values delete the corresponding query parameter.

### set_instance_protocol

Updates protocol switches, then restarts the instance.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`notcp`, `noudp`, `proxy`.

Empty values delete the corresponding query parameter.

### set_instance_traffic

Updates traffic-control values, then restarts the instance.

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Optional arguments:

`block`, `lbs`.

Empty values delete the corresponding query parameter.

### set_instance_advanced

Updates arbitrary URL fields or query parameters, then restarts the instance.

Required arguments:

| Argument | Type | Description |
|----------|------|-------------|
| `id` | string | Instance ID. |
| `parameters` | object | Key-value map. Values are converted to strings. |

The update path is shared with the structured setters, so reserved keys such as `type`, `pool`, `password`, `tunnel_address`, `tunnel_port`, `target_address`, `target_port`, and `targets` keep their special behavior. Other keys are written as URL query parameters. Empty string values delete query parameters.

Example:

```json
{
  "jsonrpc": "2.0",
  "id": 11,
  "method": "tools/call",
  "params": {
    "name": "set_instance_advanced",
    "arguments": {
      "id": "a1b2c3d4",
      "parameters": {
        "custom": "value",
        "read": "30s"
      }
    }
  }
}
```

### get_instance_config

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Returns a parsed `config` object generated from the instance's complete config URL:

| Field | Description |
|-------|-------------|
| `type` | URL scheme, `server` or `client`. |
| `password` | Password from URL userinfo, when present. |
| `tunnel_address` | URL hostname. |
| `tunnel_port` | URL port. |
| `target_address` | Target host when the path contains a single `host:port` target. |
| `target_port` | Target port when the path contains a single `host:port` target. |
| `targets` | Full target path when multiple comma-separated targets are present. |
| `parameters` | URL query parameters. Pool backend appears as `parameters.type`. |

### delete_instance

Required arguments:

| Argument | Description |
|----------|-------------|
| `id` | Instance ID. |

Behavior:

- Marks the instance as deleted.
- Stops it if it is running.
- Removes it from the master registry.
- Saves state asynchronously.
- Sends an SSE `delete` event.

The internal API key record ID `********` cannot be deleted.

## Import And Export Tools

### export_instances

Arguments: none.

Exports all non-internal instances to `nodepass.json` in the same directory as the master state file. The state file is normally stored under `gob/nodepass.gob` next to the NodePass binary, so the export file is normally:

```text
<nodepass-binary-dir>/gob/nodepass.json
```

The export includes:

| Field | Description |
|-------|-------------|
| `alias` | Instance alias. |
| `url` | Enhanced instance URL. |
| `restart` | Auto-restart policy. |
| `meta` | Peer and tag metadata. |
| `tcprx`, `tcptx`, `udprx`, `udptx` | Traffic counters. |

### import_instances

Arguments: none.

Imports instances from `nodepass.json` in the same directory as the master state file.

Behavior:

- Reads an array of exported instance objects.
- Skips entries without a valid `url`.
- Accepts only `client://` and `server://` URLs.
- Generates new instance IDs.
- Restores alias, restart policy, metadata, and traffic counters when present.
- Generates the full config URL for each imported instance.
- Starts imported instances whose `restart` flag is true.
- Saves state asynchronously.

## Network Diagnostic Tool

### tcping_target

Required arguments:

| Argument | Description |
|----------|-------------|
| `target` | Target address in `host:port` format. |

Returns a `result` object:

| Field | Description |
|-------|-------------|
| `target` | Tested address. |
| `connected` | Whether a TCP connection was established. |
| `latency` | Connection latency in milliseconds. |
| `error` | Error string when the test fails, otherwise `null`. |

Concurrency is limited internally. When the limit is saturated for more than one second, the result contains `error: "too many requests"`.

## Master Tools

### get_master_info

Arguments: none.

Returns `info` with master metadata and system statistics:

| Field | Description |
|-------|-------------|
| `mid` | Master ID. |
| `alias` | Master alias. |
| `os`, `arch`, `noc` | Operating system, architecture, and CPU count. |
| `cpu` | CPU utilization on Linux, otherwise `-1`. |
| `mem_total`, `mem_used` | Memory metrics in bytes. |
| `swap_total`, `swap_used` | Swap metrics in bytes. |
| `netrx`, `nettx` | Network receive/transmit byte counters. |
| `diskr`, `diskw` | Disk read/write byte counters. |
| `sysup` | System uptime in seconds, Linux only. |
| `ver` | NodePass version. |
| `name` | Master hostname. |
| `uptime` | Master process uptime in seconds. |
| `log` | Master log level. |
| `tls` | Master TLS mode. |
| `crt`, `key` | Master certificate and key paths. |

Detailed CPU, memory, swap, network, disk, and system uptime metrics are collected from `/proc` on Linux. On other platforms, unsupported metrics remain at default values.

### update_master_info

Required arguments:

| Argument | Description |
|----------|-------------|
| `alias` | New master alias. |

The alias must be non-empty and no longer than 256 characters. The value is persisted through the internal API key record.

## Error Codes

| Code | Meaning | Common causes |
|------|---------|---------------|
| `-32700` | Parse error | Request body is not valid JSON. |
| `-32600` | Invalid Request | `jsonrpc` is not `2.0`. |
| `-32601` | Method not found | Unknown JSON-RPC method. |
| `-32602` | Invalid params | Missing required arguments, unknown tool, invalid instance ID, invalid action, invalid type, or validation failure. |
| `-32603` | Internal error | File I/O or serialization failure during import/export. |

## cURL Examples

Set common variables:

```bash
MCP_URL="http://127.0.0.1:9090/api/v2"
API_KEY="<api-key>"
```

Initialize:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

List tools:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

List instances:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "list_instances",
      "arguments": {}
    }
  }'
```

Create a server instance:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "create_instance",
      "arguments": {
        "alias": "web",
        "type": "server",
        "tunnel_address": "0.0.0.0",
        "tunnel_port": "10101",
        "target_address": "127.0.0.1",
        "target_port": "3000",
        "log": "info",
        "pool": "0"
      }
    }
  }'
```

Restart an instance:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "control_instance",
      "arguments": {
        "id": "a1b2c3d4",
        "action": "restart"
      }
    }
  }'
```

Update TLS settings:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "tools/call",
    "params": {
      "name": "set_instance_security",
      "arguments": {
        "id": "a1b2c3d4",
        "tls": "2",
        "crt": "/etc/nodepass/server.crt",
        "key": "/etc/nodepass/server.key"
      }
    }
  }'
```

Get master information:

```bash
curl -sS -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {
      "name": "get_master_info",
      "arguments": {}
    }
  }'
```

## Operational Notes

- Configuration setters call the same URL update path. If the instance is running, NodePass stops it, waits briefly, writes the new URL, regenerates the complete config URL, and starts it again.
- `create_instance`, `control_instance`, setter tools, `delete_instance`, and `import_instances` perform some work asynchronously. A successful response means the request was accepted and state updates were scheduled; use `get_instance` or `list_instances` to observe the final runtime status.
- The special internal ID `********` stores the API key and master ID. It is hidden from `list_instances` and protected from instance mutation tools.
- `tags` in `update_instance` replace the whole tag map instead of merging with existing tags.
- MCP returns structured data in addition to text content. Automation clients should consume the structured fields where possible.
