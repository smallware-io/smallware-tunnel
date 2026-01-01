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
smallware-tunnel = { path = "../smallware-tunnel" }
```

## CLI Usage

```bash
# Basic usage
smallware-tunnel --key YOUR_API_KEY www-abc-xyz.t00.smallware.io 8080

# Using environment variable for key
export SMALLWARE_KEY=your-api-key
smallware-tunnel www-abc-xyz.t00.smallware.io 8080

# With options
smallware-tunnel --key YOUR_KEY --pool-size 5 -v www-abc-xyz.t00.smallware.io 3000
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--key` | `-k` | API key (also via `SMALLWARE_KEY` env var) |
| `--key-id` | | Key ID for JWT signing (default: "default") |
| `--pool-size` | `-n` | Number of waiting connections (default: 3) |
| `--server` | | Custom tunnel server URL |
| `--verbose` | `-v` | Enable verbose logging |

## Library Usage

### Basic Example

```rust
use smallware_tunnel::{TunnelListener, TunnelConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure the tunnel
    let config = TunnelConfig::new(
        "your-api-key".to_string(),
        "www-abc-xyz.t00.smallware.io".to_string(),
    );

    // Create a listener with 3 waiting connections
    let mut listener = TunnelListener::bind(config, 3).await?;

    // Accept incoming connections
    while let Some(stream) = listener.accept().await? {
        tokio::spawn(async move {
            // Handle the connection
            // `stream` implements AsyncRead + AsyncWrite
        });
    }

    Ok(())
}
```

### Connection Recycling

For better efficiency, connections can be recycled after clean completion:

```rust
while let Some(stream) = listener.accept().await? {
    // Process the request...

    // If the stream completed cleanly, recycle it
    if stream.is_clean_completion() {
        listener.recycle(stream).await;
    }
}
```

### Custom Configuration

```rust
let config = TunnelConfig::new(key, domain)
    .with_key_id("my-custom-key-id".to_string())
    .with_server_url("wss://custom-server.example.com/tunnels".to_string());
```

## Architecture

### Connection Pool

The `TunnelListener` maintains a pool of WebSocket connections to the tunnel server:

1. **Target pool size (N)**: Specified when creating the listener
2. **Auto-refill**: When a connection is used, new ones are created to maintain N waiting
3. **Recycling**: Clean connections can be returned for reuse
4. **Excess cleanup**: Connections above N are allowed to drain naturally

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
