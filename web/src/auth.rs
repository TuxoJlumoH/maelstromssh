//! Access control. The server only listens on 127.0.0.1, but other local
//! users and any web page open in the browser can still reach it, so:
//!
//! - every API request carries the random token from the printed link in an
//!   `Authorization` header (WebSockets: in the subprotocol list). There is
//!   no cookie: browsers send cookies to every port on 127.0.0.1, so another
//!   local program could have collected it. The link carries the token in
//!   its `#fragment`, which browsers never send to a server, and the page
//!   keeps it in `localStorage`, which is separate for each port;
//! - downloads, which the browser starts itself, use one-time tickets;
//! - the `Host` header must name this server (blocks DNS rebinding);
//! - WebSockets and requests that change something must come from this
//!   server's own page (`Origin` check, blocks cross-site requests).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::App;

/// WebSocket subprotocol the page asks for; the token is offered next to it
/// as `token-<hex>`.
pub const WS_PROTOCOL: &str = "vortexssh";
const WS_TOKEN_PREFIX: &str = "token-";

/// 32 random bytes as hex.
pub fn new_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compares without stopping at the first difference.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn has_token(app: &App, headers: &HeaderMap) -> bool {
    let bearer = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.strip_prefix("Bearer "));
    let websocket = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|p| p.trim().strip_prefix(WS_TOKEN_PREFIX));
    bearer.chain(websocket).any(|t| same(t.trim(), &app.token))
}

fn allowed_hosts(app: &App) -> [String; 2] {
    [
        format!("127.0.0.1:{}", app.port),
        format!("localhost:{}", app.port),
    ]
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

/// Requires the token; WebSockets and anything but GET also need an
/// `Origin` of this server.
pub async fn require_token(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    if !has_token(&app, req.headers()) {
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
/// no referrer, nothing cached.
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
