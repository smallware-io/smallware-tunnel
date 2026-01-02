# smallware-tunnel

A Rust client library and CLI tool for establishing tunnels to the Smallware tunnel server.

## Overview

This crate provides the smallware-tunnel library, which is the primary low-level facility that
almost all clients should use to establish tunnels throug the smallware tunnel server.

The smallware tunnel server provides "causal hosting" facilities that anybody can use to
share things on the internet, on an as-needed basis, even if they don't have a server presence
of their own:

- Smallware customers use this library, or tools based on it, to connect make websocket
  connections to wss://api.smallware.io/tunnels/...  The smallware servers then start accepting
  requests on the customers' behalf.
- When a customer's clients connect to the smallware tunnel server, they are connected though
  the server directly to the customer's websocket, so the customer, not Smallware, can serve
  the client requests.
- NO SUBSCRIPTIONS: customers purchase credits in advance, and can spend those credits by using
  smallware services. We will never charge you automatically or bother you for additional money.
- SUPER CHEAP: credit packages are available for as little as US$ 2.50, and a little bit of
  credit goes a long, long way.  We're not greedy.  The price is a reasonable markup on top
  of what we pay for the tunnel hosting hardware.

This create also provides the `smallware-tunnel` CLI tool, which you can use to establish
tunnels and forward client connections directly to local or remote TCP ports.  This is a
very thin on top of the library, and is not so easy to use.  For most use cases, you will
want to use a client that is specifically written to support that use case.  The CLI tool
provided here can be used for testing or for advanced users who can't find a more applicable
client implementation.

## Tunnel Domains

When you establish a tunnel, you need to specify the domain that your clients will connect
to.  This domain must be of the form `<service>-<anything>-<customer_id>.<shard>.smallware.io`, where:

- `<service>` indicates the type of service that clients are connecting to.  This determines
  the port they will use and how their request is routed to the correct customer.  Most often
  this will be `www`, and clients will connect using HTTPS on port 443;
- `<anything>` can be any combination of lowercase letters and digits.  Customers can choose
  this however they like to identify the particular tunneled services that they provide;
- `<customer_id>` is the smallware customer ID that is provided to every customer account;
- `<shard>` indicates the particular smallware tunnel cluster that you want to connect to. You
  can use `e0` for the default US east coast-ish cluster, or `w0` for the default US west
  coast-ish cluster.  We make no promises about where these actually are, but we will generally
  optimize their placement to best serve customers on the east and west coasts, respectively.

## Installation

### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
smallware-tunnel = "0.1"
```

### CLI

```bash
cargo install --path .
```

## CLI Usage

```bash

# Basic usage
smallware-tunnel --key YOUR_API_KEY www-whatever-custid.t00.smallware.io 8080

# Using environment variable for key
export SMALLWARE_KEY=your-api-key
smallware-tunnel www-whatever-custid.t00.smallware.io 8080
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--key` | `-k` | API key (also via `SMALLWARE_KEY` env var) This is attached to your smallware account. |
| `--key-id` | | Key ID for JWT signing (default: "default") |
| `--server` | | Custom tunnel server URL.  By default this is `wss://api.smallware.io/tunnels` you would only change this to connect to a different implementation of the smallware tunneling protocol. |
| `--trust-ca` | | Path to PEM file with an additional CA certificate to trust.  This can be used with the `--server` option if your server is using a slef-signed cert. |
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

A common use case is forwarding tunnel traffic to a local TCP port:

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

- Tokens use `iss: "customer"` for customer-issued tokens
- 30-minute expiration
- Automatic refresh when less than 15 minutes remain
- Customer ID extracted from domain name

The `JwtManager` struct is available if you need to issue your own tokens, but
you don't want to use the other parts of the tunnel library.

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
