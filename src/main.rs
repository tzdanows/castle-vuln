//! A small file-and-user service. Every endpoint works; several are deliberately unsafe.
//! See README.md for the list. The tests cover the working behaviour only.

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct AppState {
    users: Arc<Mutex<HashMap<String, StoredUser>>>,
}

#[derive(Clone, Serialize)]
pub struct StoredUser {
    pub name: String,
    /// Hex MD5 of the password.
    pub password_hash: String,
}

#[derive(Deserialize)]
pub struct NewUser {
    pub name: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct Login {
    pub name: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PingParams {
    pub host: String,
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/files/{name}", get(read_file))
        .route("/ping", get(ping))
        .route("/users", post(create_user))
        .route("/login", post(login))
        .route("/users/{name}", delete(delete_user))
        .route("/slug/{text}", get(slug))
        .with_state(state)
}

/// Serve a file from ./data by name.
async fn read_file(Path(name): Path<String>) -> Result<String, StatusCode> {
    let path = format!("data/{name}");
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)
}

/// Ping a host once and return the command's output.
async fn ping(Query(p): Query<PingParams>) -> Result<String, StatusCode> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 1 -W 1 {}", p.host))
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn create_user(State(s): State<AppState>, Json(u): Json<NewUser>) -> StatusCode {
    let hash = format!("{:x}", md5::compute(u.password.as_bytes()));
    s.users.lock().unwrap().insert(
        u.name.clone(),
        StoredUser {
            name: u.name,
            password_hash: hash,
        },
    );
    StatusCode::CREATED
}

async fn login(State(s): State<AppState>, Json(l): Json<Login>) -> StatusCode {
    let hash = format!("{:x}", md5::compute(l.password.as_bytes()));
    match s.users.lock().unwrap().get(&l.name) {
        Some(u) if u.password_hash == hash => StatusCode::OK,
        _ => StatusCode::UNAUTHORIZED,
    }
}

/// Remove a user, but only when the request carries the configured admin token.
async fn delete_user(
    State(s): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> StatusCode {
    let Ok(expected) = std::env::var("ADMIN_TOKEN") else {
        return StatusCode::FORBIDDEN;
    };
    if expected.is_empty() {
        return StatusCode::FORBIDDEN;
    }
    let authorized = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected);
    if !authorized {
        return StatusCode::FORBIDDEN;
    }

    if s.users.lock().unwrap().remove(&name).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Lower-case the text and join its words with dashes.
async fn slug(Path(text): Path<String>) -> String {
    let re = regex::Regex::new(r"[^a-z0-9]+").unwrap();
    let mut parts: Vec<&str> = Vec::new();
    let lower = text.to_lowercase();
    for part in re.split(&lower) {
        if !part.is_empty() {
            parts.push(part);
        }
    }
    let stamp = time::now_utc().tm_year + 1900;
    format!("{}-{}", parts.join("-"), stamp)
}

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app(AppState::default())).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    static ADMIN_TOKEN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct AdminTokenGuard {
        previous: Option<String>,
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    impl Drop for AdminTokenGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(token) => std::env::set_var("ADMIN_TOKEN", token),
                None => std::env::remove_var("ADMIN_TOKEN"),
            }
        }
    }

    async fn set_admin_token(token: Option<&str>) -> AdminTokenGuard {
        let lock = ADMIN_TOKEN_LOCK.lock().await;
        let previous = std::env::var("ADMIN_TOKEN").ok();
        match token {
            Some(token) => std::env::set_var("ADMIN_TOKEN", token),
            None => std::env::remove_var("ADMIN_TOKEN"),
        }
        AdminTokenGuard {
            previous,
            _lock: lock,
        }
    }

    fn state_with_user(name: &str) -> AppState {
        let state = AppState::default();
        state.users.lock().unwrap().insert(
            name.to_string(),
            StoredUser {
                name: name.to_string(),
                password_hash: "hash".to_string(),
            },
        );
        state
    }

    async fn delete_request(state: AppState, name: &str, token: Option<&str>) -> StatusCode {
        let mut req = Request::delete(format!("/users/{name}"));
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let (status, _) = text(app(state), req.body(Body::empty()).unwrap()).await;
        status
    }

    async fn text(router: Router, req: Request<Body>) -> (StatusCode, String) {
        let res = router.oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn health() {
        let (status, body) = text(app(AppState::default()), Request::get("/healthz").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn a_known_file_is_served() {
        let (status, body) = text(app(AppState::default()), Request::get("/files/hello.txt").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.trim(), "hello");
    }

    #[tokio::test]
    async fn an_unknown_file_is_404() {
        let (status, _) = text(app(AppState::default()), Request::get("/files/nope.txt").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_then_login() {
        let state = AppState::default();
        let create = Request::post("/users")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"ann","password":"hunter2"}"#))
            .unwrap();
        let (status, _) = text(app(state.clone()), create).await;
        assert_eq!(status, StatusCode::CREATED);
        let ok = Request::post("/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"ann","password":"hunter2"}"#))
            .unwrap();
        let (status, _) = text(app(state.clone()), ok).await;
        assert_eq!(status, StatusCode::OK);
        let bad = Request::post("/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"ann","password":"wrong"}"#))
            .unwrap();
        let (status, _) = text(app(state), bad).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_without_configured_admin_token_is_forbidden() {
        let state = state_with_user("ann");
        let _env = set_admin_token(None).await;
        let status = delete_request(state.clone(), "ann", Some("secret")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(state.users.lock().unwrap().contains_key("ann"));
    }

    #[tokio::test]
    async fn delete_without_authorization_header_is_forbidden() {
        let state = state_with_user("ann");
        let _env = set_admin_token(Some("secret")).await;
        let status = delete_request(state.clone(), "ann", None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(state.users.lock().unwrap().contains_key("ann"));
    }

    #[tokio::test]
    async fn delete_with_wrong_token_is_forbidden() {
        let state = state_with_user("ann");
        let _env = set_admin_token(Some("secret")).await;
        let status = delete_request(state.clone(), "ann", Some("wrong")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(state.users.lock().unwrap().contains_key("ann"));
    }

    #[tokio::test]
    async fn delete_with_correct_token_removes_user() {
        let state = state_with_user("ann");
        let _env = set_admin_token(Some("secret")).await;
        let status = delete_request(state.clone(), "ann", Some("secret")).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let missing = delete_request(state, "ann", Some("secret")).await;
        assert_eq!(missing, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn slug_joins_words() {
        let (status, body) = text(app(AppState::default()), Request::get("/slug/Hello%20World").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("hello-world-"), "{body}");
    }
}
