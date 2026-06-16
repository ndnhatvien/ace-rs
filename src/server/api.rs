//! API route definitions

use crate::server::{admin, blobs, config::ServerConfig, search, auth, error::ApiError};
use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Application state shared across routes
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<ServerConfig>,
}

#[derive(serde::Serialize)]
pub struct ModelInfo {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct GetModelsResponse {
    pub default_model: String,
    pub models: Vec<ModelInfo>,
    pub feature_flags: serde_json::Value,
}

/// Handler for connection test / model fetch in BYOK config panel
pub async fn handle_get_models(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GetModelsResponse>, ApiError> {
    // Validate token
    auth::check_bearer_token(&state.pool, &headers).await?;

    Ok(Json(GetModelsResponse {
        default_model: "byok:openai:gpt-4o".to_string(),
        models: vec![
            ModelInfo { name: "byok:openai:gpt-4o".to_string() },
            ModelInfo { name: "byok:anthropic:claude-3-5-sonnet".to_string() },
        ],
        feature_flags: serde_json::json!({
            "enablePublicBetaPage": true,
            "publicBetaEnableCustomCommands": true,
            "model_registry": "{}"
        }),
    }))
}

/// Build complete router with all routes
pub fn build_router(state: AppState) -> Router {
    Router::new()
        // API routes (auth checked in handlers)
        .route("/batch-upload", post(blobs::handle_batch_upload))
        .route("/agents/codebase-retrieval", post(search::handle_search))
        .route("/get-models", post(handle_get_models).get(handle_get_models))
        // Admin routes
        .route("/admin", get(admin::admin_login_page))
        .route("/admin/login", post(admin::admin_login))
        .route("/admin/tokens", get(admin::admin_tokens_page))
        .route("/admin/tokens", post(admin::admin_create_token))
        .route("/admin/tokens/:id/revoke", post(admin::admin_revoke_token))
        .route("/admin/logout", post(admin::admin_logout))
        .with_state(state)
}

