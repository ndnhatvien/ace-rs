//! Token management: create, verify, revoke tokens

use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::Rng;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Generate a secure random token (64 hex chars = 32 bytes)
pub fn generate_secure_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Hash a token using argon2
pub fn hash_token(token: &str) -> Result<String> {
    let salt = b"ace-server-v1-salt"; // Fixed salt for MVP
    let config = argon2::Config::default();
    argon2::hash_encoded(token.as_bytes(), salt, &config)
        .map_err(|e| anyhow!("Failed to hash token: {}", e))
}

/// Create a new token
pub async fn create_token(pool: &SqlitePool, name: &str) -> Result<(String, String)> {
    let token = generate_secure_token();
    let token_hash = hash_token(&token)?;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query!(
        "INSERT INTO tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)",
        id,
        name,
        token_hash,
        now
    )
    .execute(pool)
    .await?;

    Ok((id, token))
}

/// Verify token and update last_used_at
pub async fn verify_and_update_token(pool: &SqlitePool, token: &str) -> Result<()> {
    let token_hash = hash_token(token)?;
    let now = Utc::now().to_rfc3339();

    // Check if token exists and is not revoked
    let row = sqlx::query!(
        "SELECT id FROM tokens WHERE token_hash = ? AND revoked_at IS NULL",
        token_hash
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(record) => {
            // Update last_used_at
            sqlx::query!(
                "UPDATE tokens SET last_used_at = ? WHERE id = ?",
                now,
                record.id
            )
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

    sqlx::query!("UPDATE tokens SET revoked_at = ? WHERE id = ?", now, id)
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
        "SELECT id, name, created_at, revoked_at, last_used_at FROM tokens ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(tokens)
}

