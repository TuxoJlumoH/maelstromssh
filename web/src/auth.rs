//! Access control. The server only listens on 127.0.0.1, but other local
//! users and any web page open in the browser can still reach it, so:
//!
//! - the login link carries a random token, swapped for an `HttpOnly`,
//!   `SameSite=Strict` cookie that every API request and WebSocket needs;
//! - the `Host` header must name this server (blocks DNS rebinding);
//! - WebSockets and requests that change something must come from this
//!   server's own page (`Origin` check, blocks cross-site requests).

use std::sync::Arc;

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

use crate::{assets, App};

/// 32 random bytes as hex.
pub fn new_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Separate per port, because cookies are shared between ports.
fn cookie_name(app: &App) -> String {
    format!("vortexssh_{}", app.port)
}

/// Compares without stopping at the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn has_session(app: &App, headers: &HeaderMap) -> bool {
    let name = cookie_name(app);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .any(|(k, v)| k == name && same(v, &app.token))
}

fn allowed_hosts(app: &App) -> [String; 2] {
    [
        format!("127.0.0.1:{}", app.port),
        format!("localhost:{}", app.port),
    ]
}

#[derive(Deserialize)]
pub struct Login {
    token: String,
}

/// `GET /login?token=…`: sets the session cookie and moves on to the app,
/// so the token leaves the address bar.
pub async fn login(State(app): State<Arc<App>>, Query(q): Query<Login>) -> Response {
    if !same(&q.token, &app.token) {
        return (
            StatusCode::FORBIDDEN,
            Html(page(
                "This link is not valid. Use the link that vortexssh-web printed when it started.",
            )),
        )
            .into_response();
    }
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict",
        cookie_name(&app),
        app.token
    );
    // A page that moves on by itself rather than a redirect: when the
    // browser arrives from the file opened by xdg-open, a redirect chain
    // counts as cross-site and the SameSite=Strict cookie would be left off
    // the request for `/`. A navigation started by this page is same-site.
    let mut response = Html(
        "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=/\">\
         <title>VortexSSH</title><a href=\"/\">Open VortexSSH</a>\n",
    )
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// `GET /`: the app, for a browser that has logged in.
pub async fn index(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if has_session(&app, &headers) {
        assets::index()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Html(page(
                "Open the link that vortexssh-web printed when it started.",
            )),
        )
            .into_response()
    }
}

/// Rejects requests whose `Host` is not this server.
pub async fn check_host(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !allowed_hosts(&app).iter().any(|a| a == host) {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    next.run(req).await
}

/// Requires the session cookie; WebSockets and anything but GET also need
/// an `Origin` of this server.
pub async fn require_session(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    if !has_session(&app, req.headers()) {
        return (StatusCode::UNAUTHORIZED, "not logged in").into_response();
    }
    let is_websocket = req.headers().contains_key(header::UPGRADE);
    if is_websocket || req.method() != Method::GET {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
            .unwrap_or("");
        let ok = allowed_hosts(&app)
            .iter()
            .any(|h| origin == format!("http://{h}"));
        if !ok {
            return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
        }
    }
    next.run(req).await
}

/// Locks the page down: no framing, no third-party scripts or connections,
/// no referrer (the login URL holds the token), nothing cached.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    let set = |h: &mut HeaderMap, name: header::HeaderName, value: &'static str| {
        h.insert(name, HeaderValue::from_static(value));
    };
    // xterm.js adds <style> elements for its theme, hence 'unsafe-inline'
    // for styles only.
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; \
         frame-ancestors 'none'; form-action 'self'",
    );
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::CACHE_CONTROL, "no-store");
    response
}

/// A minimal standalone page for login errors.
fn page(message: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>VortexSSH</title>\
         <link rel=\"stylesheet\" href=\"/assets/app.css\"></head>\
         <body class=\"notice\"><main><img src=\"/assets/icon.svg\" alt=\"\" width=\"64\" height=\"64\">\
         <h1>VortexSSH</h1><p>{message}</p></main></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn comparison() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
    }
}
