//! A small file-and-user service. Every endpoint works; several are deliberately unsafe.
//! See README.md for the list. The tests cover the working behaviour only.

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
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
/// Validate that `name` is a single plain file name (no path separators, no `.` or `..`).
fn is_valid_filename(name: &str) -> bool {
    if name.is_empty() || name.contains("/") || name.contains("\\") {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    true
}

/// Serve a file from ./data by name.
async fn read_file(Path(name): Path<String>) -> Result<String, StatusCode> {
    if !is_valid_filename(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = format!("data/{name}");
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)
}

/// A host is accepted only if it contains hostname or IP-literal characters and
/// cannot be mistaken for a command-line flag.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

/// Ping a host once and return the command's output.
async fn ping(Query(p): Query<PingParams>) -> Result<String, StatusCode> {
    if !valid_host(&p.host) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let out = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("1")
        .arg(&p.host)
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

/// Remove a user.
async fn delete_user(State(s): State<AppState>, Path(name): Path<String>) -> StatusCode {
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
    async fn path_traversal_is_rejected() {
        let (status, _) = text(app(AppState::default()), Request::get("/files/..%2FCargo.toml").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
    async fn ping_rejects_shell_metacharacters_and_spaces() {
        for host in ["localhost;id", "local host"] {
            let req = Request::get(format!("/ping?host={}", host.replace(' ', "%20")))
                .body(Body::empty())
                .unwrap();
            let (status, _) = text(app(AppState::default()), req).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "host {host:?} was accepted");
        }
    }

    #[test]
    fn valid_host_accepts_hostnames_and_ip_literals() {
        for host in [
            "localhost",
            "example.com",
            "api-1.example.com",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
        ] {
            assert!(valid_host(host), "host {host:?} was rejected");
        }
    }

    #[test]
    fn valid_host_rejects_leading_dashes_and_injection_attempts() {
        for host in [
            "",
            "-c",
            "--help",
            "localhost;id",
            "local host",
            "localhost$(id)",
            "localhost|id",
            "localhost&id",
        ] {
            assert!(!valid_host(host), "host {host:?} was accepted");
        }
    }

    #[tokio::test]
    async fn slug_joins_words() {
        let (status, body) = text(app(AppState::default()), Request::get("/slug/Hello%20World").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("hello-world-"), "{body}");
    }
}
