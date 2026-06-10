//! Token management: create, verify, revoke tokens

use anyhow::{anyhow, Result};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use chrono::Utc;
use rand::Rng;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Generate a secure random token (64 hex chars = 32 bytes)
pub fn generate_secure_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Hash a token using argon2 (RustCrypto `argon2` crate v0.5)
pub fn hash_token(token: &str) -> Result<String> {
    // Fixed salt for MVP (deterministic so we can look tokens up by hash).
    // NOTE: For production, use a per-token random salt + separate lookup column.
    let salt = SaltString::encode_b64(b"ace-server-v1-salt")
        .map_err(|e| anyhow!("Failed to build salt: {}", e))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash token: {}", e))?;
    Ok(hash.to_string())
}

/// Create a new token
pub async fn create_token(pool: &SqlitePool, name: &str) -> Result<(String, String)> {
    let token = generate_secure_token();
    let token_hash = hash_token(&token)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query("INSERT INTO tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(name)
        .bind(&token_hash)
        .bind(&now)
        .execute(pool)
        .await?;

    Ok((id, token))
}

/// Verify token and update last_used_at
pub async fn verify_and_update_token(pool: &SqlitePool, token: &str) -> Result<()> {
    let token_hash = hash_token(token)?;
    let now = Utc::now().to_rfc3339();

    // Check if token exists and is not revoked
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM tokens WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((id,)) => {
            // Update last_used_at
            sqlx::query("UPDATE tokens SET last_used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&id)
                .execute(pool)
                .await?;
            Ok(())
        }
        None => Err(anyhow!("Invalid or revoked token")),
    }
}

/// Revoke a token by ID
pub async fn revoke_token(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE tokens SET revoked_at = ? WHERE id = ?")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Token row for admin UI
#[derive(Debug, sqlx::FromRow)]
pub struct TokenRow {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// List all tokens
pub async fn list_tokens(pool: &SqlitePool) -> Result<Vec<TokenRow>> {
    let tokens = sqlx::query_as::<_, TokenRow>(
        "SELECT id, name, created_at, revoked_at, last_used_at FROM tokens ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(tokens)
}
