//! Server configuration from environment variables

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub db_path: PathBuf,
    pub admin_password: String,
    pub session_secret: String,
}

impl ServerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let bind_addr = std::env::var("ACE_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .map_err(|e| anyhow!("Invalid ACE_BIND_ADDR: {}", e))?;

        let db_path = std::env::var("ACE_DB_PATH")
            .unwrap_or_else(|_| "/data/ace-server.db".to_string())
            .into();

        let admin_password = std::env::var("ACE_ADMIN_PASSWORD")
            .map_err(|_| anyhow!("ACE_ADMIN_PASSWORD environment variable is required"))?;

        if admin_password.len() < 8 {
            return Err(anyhow!(
                "ACE_ADMIN_PASSWORD must be at least 8 characters long"
            ));
        }

        let session_secret = std::env::var("ACE_SESSION_SECRET")
            .map_err(|_| anyhow!("ACE_SESSION_SECRET environment variable is required"))?;

        if session_secret.len() < 16 {
            return Err(anyhow!(
                "ACE_SESSION_SECRET must be at least 16 characters long"
            ));
        }

        Ok(Self {
            bind_addr,
            db_path,
            admin_password,
            session_secret,
        })
    }
}
