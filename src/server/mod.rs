//! Self-hosted server module for local-first indexing and search

#[cfg(feature = "server")]
pub mod admin;
#[cfg(feature = "server")]
pub mod api;
#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod blobs;
#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod db;
#[cfg(feature = "server")]
pub mod error;
#[cfg(feature = "server")]
pub mod search;
#[cfg(feature = "server")]
pub mod tokens;

// Re-export key types for convenience
#[cfg(feature = "server")]
pub use config::ServerConfig;
#[cfg(feature = "server")]
pub use error::ApiError;
