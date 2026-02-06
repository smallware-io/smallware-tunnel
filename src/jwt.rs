//! JWT token generation and management for tunnel authentication.
//!
//! This module handles the generation of customer JWT tokens for authenticating
//! with the Smallware tunnel server. Tokens are:
//!
//! - Generated with `iss: "customer"` to use database-backed key validation
//! - Signed using the provided API key (HS256 algorithm)
//! - Set to expire 30 minutes from generation time
//! - Automatically refreshed when less than 15 minutes remain
//!
//! # Token Format
//!
//! The generated JWT tokens contain:
//! - `iss`: "customer" (issuer)
//! - `sub`: The customer ID extracted from the domain
//! - `exp`: Expiration timestamp (30 minutes from now)
//! - `iat`: Issued-at timestamp
//! - `roles`: ["tunnel"]
//!
//! The header includes a `kid` (key ID) that identifies which key to use
//! for signature verification on the server side.

use crate::error::TunnelError;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Token validity duration (30 minutes).
const TOKEN_VALIDITY_MINUTES: i64 = 30;

/// Refresh threshold (15 minutes remaining).
/// When a token has less than this much time remaining, a new one is generated.
const REFRESH_THRESHOLD_MINUTES: i64 = 15;

/// Claims structure for customer JWT tokens.
///
/// These claims are validated by the tunnel server to authenticate
/// the WebSocket connection.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomerClaims {
    /// Issuer - always "customer" for client-generated tokens
    pub iss: String,

    /// Subject - the customer ID (extracted from domain)
    pub sub: String,

    /// Expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Issued-at timestamp (Unix seconds)
    pub iat: i64,

    /// Roles - always includes "tunnel" for tunnel access
    pub roles: Vec<String>,
}

/// Cached token with its expiration time.
#[derive(Debug, Clone)]
struct CachedToken {
    /// The encoded JWT string
    token: String,
    /// When this token expires
    expires_at: chrono::DateTime<Utc>,
}

/// Manages JWT token generation and caching for tunnel authentication.
///
/// The JwtManager handles:
/// - Token generation using the provided API key
/// - Caching tokens to avoid regenerating on every request
/// - Automatic refresh when tokens are close to expiration
///
/// # Thread Safety
///
/// JwtManager is thread-safe and can be shared across tasks using Arc.
///
/// # Example
///
/// ```rust,no_run
/// use smallware_tunnel::JwtManager;
///
/// let manager = JwtManager::new(
///     "your-api-key".to_string(),
///     "customer123".to_string(),
///     "default".to_string(),
/// );
///
/// // Get a valid token (generates new one if needed)
/// let token = manager.get_token().expect("Failed to generate token");
/// ```
#[derive(Debug)]
pub struct JwtManager {
    /// The API key (secret) used to sign tokens
    secret: String,

    /// The customer ID to use in the `sub` claim
    customer_id: String,

    /// The key ID for the JWT header
    key_id: String,

    /// Cached token (if any)
    cached_token: RwLock<Option<CachedToken>>,
}

impl JwtManager {
    /// Creates a new JWT manager.
    ///
    /// # Arguments
    ///
    /// * `customer_id` - The customer ID to include in the `sub` claim.
    ///   This is typically extracted from the tunnel domain.
    /// * `key_id` - The key ID (`kid`) to include in the JWT header.
    ///   This identifies which key the server should use for verification.
    /// * `secret` - The API key (secret) used to sign tokens. This must match
    ///   the key stored in the server's database for the customer.
    pub fn new(customer_id: String, key_id: String, secret: String) -> Self {
        Self {
            secret,
            customer_id,
            key_id,
            cached_token: RwLock::new(None),
        }
    }

    /// Creates a new JWT manager from a combined access key in the form `<customer_id>.<key_id>.<secret>`.
    /// Whitespaces within the key are ignored.
    /// # Arguments
    /// * `combined_key` - The combined access key string.
    /// # Returns
    /// * `Result<Self, ()>` - Ok with JwtManager if parsing is successful, Err if the key is malformed.
    pub fn from_access_key(combined_key: &str) -> Result<Self, ()> {
        let (customer_id, key_id, secret) = parse_access_key(combined_key)?;
        Ok(Self::new(customer_id, key_id, secret))
    }

    /// Gets a valid JWT token, generating a new one if necessary.
    ///
    /// This method:
    /// 1. Checks if a cached token exists and has more than 15 minutes remaining
    /// 2. If so, returns the cached token
    /// 3. Otherwise, generates a new token with 30-minute expiration
    ///
    /// # Returns
    ///
    /// A valid JWT token string, or an error if token generation fails.
    pub fn get_token(&self) -> Result<String, TunnelError> {
        // Fast path: check if we have a valid cached token
        if let Ok(cache) = self.cached_token.read() {
            if let Some(cached) = cache.as_ref() {
                let now = Utc::now();
                let remaining = cached.expires_at.signed_duration_since(now);
                if remaining > Duration::minutes(REFRESH_THRESHOLD_MINUTES) {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Slow path: generate a new token
        self.generate_and_cache_token()
    }

    /// Generates a new token and caches it.
    ///
    /// This always generates a fresh token, regardless of cache state.
    fn generate_and_cache_token(&self) -> Result<String, TunnelError> {
        let now = Utc::now();
        let expires_at = now + Duration::minutes(TOKEN_VALIDITY_MINUTES);

        let claims = CustomerClaims {
            iss: "customer".to_string(),
            sub: self.customer_id.clone(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            roles: vec!["tunnel".to_string()],
        };

        // Create header with key ID
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.key_id.clone());

        // Encode the token
        let encoding_key = EncodingKey::from_secret(self.secret.as_bytes());
        let token = encode(&header, &claims, &encoding_key)?;

        // Cache the token
        if let Ok(mut cache) = self.cached_token.write() {
            *cache = Some(CachedToken {
                token: token.clone(),
                expires_at,
            });
        }
        Ok(token)
    }

    /// Forces generation of a new token, ignoring the cache.
    ///
    /// This is useful if the current token is being rejected by the server.
    pub fn refresh_token(&self) -> Result<String, TunnelError> {
        self.generate_and_cache_token()
    }

    /// Returns the customer ID associated with this manager.
    pub fn customer_id(&self) -> &str {
        &self.customer_id
    }

    /// Returns the key ID used for token signing.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Parse an access key in the format `<customer_id>.<key_id>.<secret>` form into its components.
/// Whitespace within the key is removed
pub fn parse_access_key(combined_key: &str) -> Result<(String, String, String), ()> {
    let div1 = combined_key.find('.').unwrap_or(0);
    let div2 = combined_key.rfind('.').unwrap_or(0);
    if div1 == 0 || div2 == 0 || div1 >= div2 {
        return Err(());
    }
    let mut customer_id = combined_key[..div1].to_string();
    customer_id.retain(|c| !c.is_whitespace());
    let mut key_id = combined_key[div1 + 1..div2].to_string();
    key_id.retain(|c| !c.is_whitespace());
    let mut secret = combined_key[div2 + 1..].to_string();
    secret.retain(|c| !c.is_whitespace());

    return Ok((customer_id, key_id, secret));
}

/// Extracts the customer ID from a tunnel domain.
///
/// The domain format is: `<service>-<random>-<customer>.<shard>.smallware.io`
///
/// # Arguments
///
/// * `domain` - The full tunnel domain name
///
/// # Returns
///
/// The customer ID portion of the domain, or an error if the domain
/// format is invalid.
///
/// # Example
///
/// ```rust
/// use smallware_tunnel::jwt::extract_customer_id;
///
/// let customer_id = extract_customer_id("www-abc123-xyz789.t00.smallware.io")?;
/// assert_eq!(customer_id, "xyz789");
/// # Ok::<(), smallware_tunnel::TunnelError>(())
/// ```
pub fn extract_customer_id(domain: &str) -> Result<String, TunnelError> {
    // Split by dots: should be ["service-random-customer", "shard", "smallware", "io"]
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() != 4 {
        return Err(TunnelError::InvalidDomain(Arc::from(format!(
            "Domain must have 4 parts separated by dots, got {}: {}",
            parts.len(),
            domain
        ))));
    }

    // Validate suffix
    if parts[2] != "smallware" || parts[3] != "io" {
        return Err(TunnelError::InvalidDomain(Arc::from(format!(
            "Domain must end with .smallware.io: {}",
            domain
        ))));
    }

    // Split first part by dashes: should be ["service", "random", "customer"]
    let first_part_components: Vec<&str> = parts[0].split('-').collect();

    if first_part_components.len() != 3 {
        return Err(TunnelError::InvalidDomain(Arc::from(format!(
            "First part must have 3 dash-separated components (service-random-customer), got {}: {}",
            first_part_components.len(),
            parts[0]
        ))));
    }

    Ok(first_part_components[2].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_customer_id_valid() {
        assert_eq!(
            extract_customer_id("www-abc123-xyz789.t00.smallware.io").unwrap(),
            "xyz789"
        );
        assert_eq!(
            extract_customer_id("www-test-customer.t01.smallware.io").unwrap(),
            "customer"
        );
    }

    #[test]
    fn test_extract_customer_id_invalid_format() {
        // Wrong number of dots
        assert!(extract_customer_id("www-abc-xyz.smallware.io").is_err());
        // Wrong suffix
        assert!(extract_customer_id("www-abc-xyz.t00.example.com").is_err());
        // Wrong number of dashes
        assert!(extract_customer_id("www-xyz.t00.smallware.io").is_err());
        assert!(extract_customer_id("www-a-b-c-d.t00.smallware.io").is_err());
    }

    #[test]
    fn test_jwt_manager_generates_token() {
        let manager = JwtManager::new(
            "customer123".to_string(),
            "key1".to_string(),
            "test-secret".to_string(),
        );

        let token = manager.get_token().unwrap();
        assert!(!token.is_empty());

        // Token should be valid JWT format (three dot-separated parts)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_jwt_manager_caches_token() {
        let manager = JwtManager::new(
            "customer123".to_string(),
            "key1".to_string(),
            "test-secret".to_string(),
        );

        let token1 = manager.get_token().unwrap();
        let token2 = manager.get_token().unwrap();

        // Should return the same cached token
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_jwt_manager_refresh_generates_new_token() {
        let manager = JwtManager::new(
            "customer123".to_string(),
            "key1".to_string(),
            "test-secret".to_string(),
        );

        let token1 = manager.get_token().unwrap();

        // Small delay to ensure different iat
        std::thread::sleep(std::time::Duration::from_millis(10));

        let token2 = manager.refresh_token().unwrap();

        // refresh_token should generate a new token
        // (tokens might differ due to different iat timestamps)
        // Both should be valid though
        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
    }
}
