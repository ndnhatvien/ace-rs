//! Authentication helpers

use crate::server::{error::ApiError, tokens::verify_and_update_token};
use axum::http::{header::AUTHORIZATION, HeaderMap};
use sqlx::SqlitePool;
use tower_sessions::Session;

/// Extract and verify bearer token from headers
pub async fn check_bearer_token(pool: &SqlitePool, headers: &HeaderMap) -> Result<(), ApiError> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized)?;

    verify_and_update_token(pool, token)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(())
}

/// Check if admin session is valid
pub async fn check_admin_session(session: &Session) -> bool {
    session
        .get::<bool>("admin_logged_in")
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false)
}

