# smallware-tunnel

A Rust client library and CLI tool for establishing tunnels to the Smallware tunnel server.

## Overview

This crate provides:
- **Library**: A Tokio-based API for establishing tunnel connections from Rust applications
- **CLI**: A command-line tool for proxying traffic from tunnel domains to local ports

## Installation

### CLI

```bash
cargo install --path .
```

### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
smallware-tunnel = "0.1"
```

## CLI Usage

```bash
# Basic usage
smallware-tunnel --key YOUR_API_KEY www-abc-xyz.t00.smallware.io 8080

# Using environment variable for key
export SMALLWARE_KEY=your-api-key
smallware-tunnel www-abc-xyz.t00.smallware.io 8080
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--key` | `-k` | API key (also via `SMALLWARE_KEY` env var) |
| `--key-id` | | Key ID for JWT signing (default: "default") |
| `--server` | | Custom tunnel server URL |
| `--trust-ca` | | Path to PEM file with CA certificate to trust |
| `--verbose` | `-v` | Enable verbose logging |

## Library Usage

### Basic Example

```rust
use smallware_tunnel::{TunnelListener, TunnelConfig, TunnelError};
use futures::{SinkExt, StreamExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure the tunnel
    let config = TunnelConfig::new(
        "your-api-key".to_string(),
        "www-abc-xyz.t00.smallware.io".to_string(),
    );

    // Create a listener
    let listener = TunnelListener::new(config)?;

    // Accept incoming connections
    loop {
        match listener.accept().await {
            Ok((sink, stream)) => {
                tokio::spawn(async move {
                    // `sink` implements futures::Sink<Bytes>
                    // `stream` implements futures::Stream<Item = Result<Bytes, TunnelError>>
                });
            }
            Err(TunnelError::ListenerClosed) => break,
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    Ok(())
}
```

### Forwarding to Local Services

The most common use case is forwarding tunnel traffic to a local TCP port:

```rust
use smallware_tunnel::{TunnelListener, TunnelConfig, forward_tunnel_tcp};
use std::net::SocketAddr;

let listener = TunnelListener::new(config)?;
let local_addr: SocketAddr = "127.0.0.1:8080".parse()?;

loop {
    let (sink, stream) = listener.accept().await?;
    tokio::spawn(async move {
        if let Err(e) = forward_tunnel_tcp(sink, stream, local_addr).await {
            eprintln!("Forward error: {}", e);
        }
    });
}
```

### Custom Configuration

```rust
use std::path::PathBuf;

let config = TunnelConfig::new(key, domain)
    .with_key_id("my-custom-key-id".to_string())
    .with_server_url("wss://custom-server.example.com/tunnels".to_string())
    .with_trust_ca(PathBuf::from("/path/to/ca.pem"));
```

## Architecture

### Connection Recycling

The `TunnelListener` automatically manages WebSocket connection lifecycle:

1. **On-demand connections**: Each `accept()` call establishes a new WebSocket connection or reuses a recycled one
2. **Automatic recycling**: When both `TunnelSink` and `TunnelStream` complete cleanly (graceful EOF), the underlying WebSocket is automatically returned for reuse
3. **Rendezvous handoff**: Recycled connections are handed directly to waiting `accept()` calls via a rendezvous channel, minimizing latency

### Data Flow

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│  Remote Client  │◄───────►│  Tunnel Server  │◄───────►│  Your App       │
│                 │  HTTPS  │  api.smallware  │  WSS    │  (TunnelListener)│
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

### Protocol

- WebSocket binary messages for data transport
- Empty binary message signals EOF and shutdown independently in both directions
- Server -> client text messages for control signals:
  - `CONNECT: <ip>` - Proxy client connected
  - `DROP: <reason>` - Error on the proxy connection.  The websocket can still
    be reused for a new client.
- Client -> server text messages for control signals:
  - `RESET` - The connection has been recycled.  Start waiting for a new proxy
    connection.  This is only valid after Client -> server EOF and server ->
    client EOF or DROP.  Sending this in other situations will cause the connection
    to close.

## JWT Authentication

The library automatically manages JWT tokens:

- Tokens use `iss: "customer"` for database-backed key validation
- 30-minute expiration
- Automatic refresh when less than 15 minutes remain
- Customer ID extracted from domain name

## Domain Format

Tunnel domains follow this format:

```
<service>-<random>-<customer>.<shard>.smallware.io
```

Example: `www-abc123-xyz789.t00.smallware.io`

- **service**: The tunnel service type (e.g., "www")
- **random**: A random identifier
- **customer**: Your customer ID
- **shard**: The server shard (e.g., "t00", "t01")

## Error Handling

The library provides detailed error types via `TunnelError`:

- `ConnectionFailed` - Failed to connect to server
- `WebSocketError` - WebSocket protocol error
- `AuthenticationFailed` - JWT rejected by server
- `InvalidDomain` - Domain format invalid
- `ListenerClosed` - Listener has been shut down
- `IoError` - Underlying I/O error

## License

MIT
