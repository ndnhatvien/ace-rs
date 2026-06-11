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
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    // Generate a random salt for each token
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(token.as_bytes(), &salt)
        .map(|hash| hash.to_string())
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
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let now = Utc::now().to_rfc3339();

    // Get all non-revoked tokens and verify against each hash
    // This is needed because we can't hash the incoming token to match it directly
    // (each hash has a unique salt)
    let rows = sqlx::query!(
        "SELECT id, token_hash FROM tokens WHERE revoked_at IS NULL"
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        // Try to verify the token against this hash
        let parsed_hash = PasswordHash::new(&row.token_hash)
            .map_err(|e| anyhow!("Failed to parse hash: {}", e))?;

        if Argon2::default()
            .verify_password(token.as_bytes(), &parsed_hash)
            .is_ok()
        {
            // Found matching token, update last_used_at
            sqlx::query!(
                "UPDATE tokens SET last_used_at = ? WHERE id = ?",
                now,
                row.id
            )
            .execute(pool)
            .await?;
            return Ok(());
        }
    }

    Err(anyhow!("Invalid or revoked token"))
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

