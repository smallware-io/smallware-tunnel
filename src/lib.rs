//! Smallware Tunnel Client Library
//!
//! This library provides Rust developers with the ability to establish tunnels
//! from their applications to the Smallware tunnel server, enabling remote access
//! to local services through secure WebSocket connections.
//!
//! # Overview
//!
//! The library manages WebSocket connections to the tunnel server. When a remote
//! client connects to your tunnel domain, the server routes the connection through
//! the WebSocket, and your application receives a [`TunnelSink`] and [`TunnelStream`]
//! pair for bidirectional communication.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
//! │  Remote Client  │◄───────►│  Tunnel Server  │◄───────►│  Your App       │
//! │                 │  HTTPS  │api.smallware.io │  WSS    │ (TunnelListener)│
//! └─────────────────┘         └─────────────────┘         └─────────────────┘
//!                                                                  │
//!                                                                  ▼
//!                                                         ┌─────────────────┐
//!                                                         │  Local Service  │
//!                                                         │  (localhost:N)  │
//!                                                         └─────────────────┘
//! ```
//!
//! # Connection Recycling
//!
//! The library automatically manages WebSocket connection recycling:
//!
//! - When a [`TunnelStream`] and [`TunnelSink`] complete cleanly (graceful EOF),
//!   the underlying WebSocket connection is returned to a recycling pool.
//!
//! - The next call to [`TunnelListener::accept()`] will reuse a recycled connection
//!   if one is available, avoiding the overhead of establishing a new WebSocket.
//!
//! - If both the stream and sink are dropped without errors, the connection
//!   becomes available for reuse. If either encounters an error, the connection
//!   is discarded.
//!
//! # JWT Authentication
//!
//! The library automatically generates and refreshes JWT tokens for authentication:
//!
//! - Tokens are generated using the provided API key
//! - Tokens have a 30-minute expiration
//! - A new token is generated when the current one has less than 15 minutes remaining
//! - The customer ID is extracted from the domain name

pub mod error;
pub mod forward;
pub mod jwt;
pub mod listener;
pub mod proc_machines;
mod scitemstream;
mod spitemsink;
pub mod spsc;
pub mod trace_id;
pub mod tunnel_protocol;

pub use error::TunnelError;
pub use forward::{forward_tunnel, forward_tunnel_tcp, ForwardStats};
pub use jwt::JwtManager;
pub use listener::{
    parse_key, TunnelClientInfo, TunnelConfig, TunnelListener, TunnelSink, TunnelStream,
};
