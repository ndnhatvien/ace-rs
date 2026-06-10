//! Admin UI routes and HTML rendering

use crate::server::{config::ServerConfig, error::ApiError, tokens};
use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tower_sessions::Session;

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenForm {
    pub name: String,
}

/// Admin login page
pub async fn admin_login_page() -> Html<String> {
    Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>ACE Server Admin</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        input[type=password] { padding: 8px; width: 300px; }
        button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>ACE Server Admin</h1>
    <form method="POST" action="/admin/login">
        <p><label>Password: <input type="password" name="password" required /></label></p>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"#
        .to_string(),
    )
}

/// Handle admin login
pub async fn admin_login(
    State(config): State<Arc<ServerConfig>>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if form.password == config.admin_password {
        let _ = session.insert("admin_logged_in", true).await;
        Redirect::to("/admin/tokens")
    } else {
        // Basic rate limiting: sleep 1s on failure
        tokio::time::sleep(Duration::from_secs(1)).await;
        Redirect::to("/admin?error=1")
    }
}

/// Admin tokens list page
pub async fn admin_tokens_page(
    State(pool): State<SqlitePool>,
    session: Session,
) -> Result<Html<String>, impl IntoResponse> {
    // Check admin session
    if !crate::server::auth::check_admin_session(&session).await {
        return Err(Redirect::to("/admin"));
    }

    let token_rows = tokens::list_tokens(&pool).await.map_err(|_| Redirect::to("/admin"))?;

    let mut html = String::from(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Manage Tokens</title>
    <style>
        body { font-family: sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        input[type=text] { padding: 8px; width: 300px; }
        button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; margin: 2px; }
        button:hover { background: #0056b3; }
        button.danger { background: #dc3545; }
        button.danger:hover { background: #c82333; }
    </style>
</head>
<body>
    <h1>API Tokens</h1>
    <form method="POST" action="/admin/tokens">
        <label>Token name: <input type="text" name="name" required /></label>
        <button type="submit">Create Token</button>
    </form>
    <h2>Existing Tokens</h2>
    <table>
    <tr><th>Name</th><th>Created</th><th>Last Used</th><th>Status</th><th>Actions</th></tr>
"#,
    );

    for token_row in token_rows {
        let status = if token_row.revoked_at.is_some() {
            "Revoked"
        } else {
            "Active"
        };
        let revoke_btn = if token_row.revoked_at.is_none() {
            format!(
                r#"<form method="POST" action="/admin/tokens/{}/revoke" style="display:inline"><button class="danger">Revoke</button></form>"#,
                token_row.id
            )
        } else {
            String::new()
        };

        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            token_row.name,
            token_row.created_at,
            token_row.last_used_at.unwrap_or_default(),
            status,
            revoke_btn
        ));
    }

    html.push_str("</table></body></html>");
    Ok(Html(html))
}

/// Handle create token
pub async fn admin_create_token(
    State(pool): State<SqlitePool>,
    session: Session,
    Form(form): Form<CreateTokenForm>,
) -> Result<Html<String>, impl IntoResponse> {
    // Check admin session
    if !crate::server::auth::check_admin_session(&session).await {
        return Err(Redirect::to("/admin"));
    }

    let (_id, token) = tokens::create_token(&pool, &form.name).await.map_err(|_| Redirect::to("/admin"))?;

    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Token Created</title>
    <style>
        body {{ font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        pre {{ background:#f0f0f0; padding:1em; font-size:14px; overflow-x: auto; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .warning {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Token Created</h1>
    <p class="warning">COPY THIS TOKEN NOW - IT WILL NOT BE SHOWN AGAIN:</p>
    <pre>{}</pre>
    <p><a href="/admin/tokens">Back to token list</a></p>
</body>
</html>
"#,
        token
    );

    Ok(Html(html))
}

/// Handle revoke token
pub async fn admin_revoke_token(
    State(pool): State<SqlitePool>,
    session: Session,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Redirect, impl IntoResponse> {
    // Check admin session
    if !crate::server::auth::check_admin_session(&session).await {
        return Err(Redirect::to("/admin"));
    }

    tokens::revoke_token(&pool, &id).await.map_err(|_| Redirect::to("/admin"))?;
    Ok(Redirect::to("/admin/tokens"))
}

/// Handle logout
pub async fn admin_logout(session: Session) -> Redirect {
    let _ = session.delete().await;
    Redirect::to("/admin")
}

