//! API route definitions

use crate::server::{admin, blobs, config::ServerConfig, search};
use axum::{routing::{get, post}, Router};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Application state shared across routes
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<ServerConfig>,
}

/// Build complete router with all routes
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // API routes (auth checked in handlers)
        .route("/batch-upload", post(blobs::handle_batch_upload))
        .route("/agents/codebase-retrieval", post(search::handle_search))
        // Admin routes
        .route("/admin", get(admin::admin_login_page))
        .route("/admin/login", post(admin::admin_login))
        .route("/admin/tokens", get(admin::admin_tokens_page))
        .route("/admin/tokens", post(admin::admin_create_token))
        .route("/admin/tokens/:id/revoke", post(admin::admin_revoke_token))
        .route("/admin/logout", post(admin::admin_logout))
        .with_state(state)
}

