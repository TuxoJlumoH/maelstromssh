//! Router tests: access control, security headers, assets and the profile
//! API, run against the real router without a network socket.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::{router, App};

const PORT: u16 = 18999;
const HOST: &str = "127.0.0.1:18999";
const ORIGIN: &str = "http://127.0.0.1:18999";

fn app() -> Arc<App> {
    Arc::new(App {
        token: "a".repeat(64),
        port: PORT,
        conns: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
    })
}

fn cookie() -> String {
    format!("vortexssh_{PORT}={}", "a".repeat(64))
}

/// A request with the right Host, plus the given headers.
fn request(method: Method, uri: &str, headers: &[(&str, &str)], body: Body) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(body).unwrap()
}

async fn send(req: Request<Body>) -> Response {
    router(app()).oneshot(req).await.unwrap()
}

async fn text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 22).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn login_sets_a_cookie_and_redirects() {
    let token = "a".repeat(64);
    let r = send(request(
        Method::GET,
        &format!("/login?token={token}"),
        &[],
        Body::empty(),
    ))
    .await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()[header::LOCATION], "/");
    let set = r.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set.starts_with(&cookie()), "{set}");
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
}

#[tokio::test]
async fn wrong_or_missing_token_is_refused() {
    let wrong = format!("/login?token={}", "b".repeat(64));
    let r = send(request(Method::GET, &wrong, &[], Body::empty())).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(!r.headers().contains_key(header::SET_COOKIE));

    let r = send(request(Method::GET, "/login", &[], Body::empty())).await;
    assert!(r.status().is_client_error());
    assert!(!r.headers().contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn the_app_needs_a_session() {
    let r = send(request(Method::GET, "/", &[], Body::empty())).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(!text(r).await.contains("app.js"));

    let bad = format!("vortexssh_{PORT}={}", "b".repeat(64));
    let other_port = format!("vortexssh_8022={}", "a".repeat(64));
    for c in [bad.as_str(), other_port.as_str()] {
        let r = send(request(Method::GET, "/", &[("cookie", c)], Body::empty())).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{c}");
    }

    let c = format!("theme=dark; {}", cookie());
    let r = send(request(Method::GET, "/", &[("cookie", &c)], Body::empty())).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(text(r).await.contains("/assets/app.js"));
}

#[tokio::test]
async fn api_routes_need_a_session() {
    let routes = [
        (Method::GET, "/api/hosts"),
        (Method::POST, "/api/profiles"),
        (Method::DELETE, "/api/profiles/x"),
        (Method::GET, "/api/conn/1/download?path=/etc/passwd"),
        (Method::PUT, "/api/conn/1/upload?path=/tmp/x"),
        (Method::GET, "/ws"),
    ];
    for (method, uri) in routes {
        let r = send(request(
            method.clone(),
            uri,
            &[("origin", ORIGIN)],
            Body::empty(),
        ))
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn foreign_hosts_are_refused() {
    // DNS rebinding: a page on evil.example resolving to 127.0.0.1.
    for host in ["evil.example:18999", "127.0.0.1:8022", "127.0.0.1", ""] {
        let req = Request::builder()
            .uri("/")
            .header(header::HOST, host)
            .header(header::COOKIE, cookie())
            .body(Body::empty())
            .unwrap();
        let r = send(req).await;
        assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST, "{host:?}");
    }
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "localhost:18999")
        .header(header::COOKIE, cookie())
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(req).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn changes_and_websockets_need_this_origin() {
    let c = cookie();
    let ws = [
        ("cookie", c.as_str()),
        ("upgrade", "websocket"),
        ("connection", "upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ];
    for origin in [
        None,
        Some("http://evil.example"),
        Some("http://127.0.0.1:8022"),
        Some("null"),
    ] {
        let mut headers = ws.to_vec();
        if let Some(o) = origin {
            headers.push(("origin", o));
        }
        let r = send(request(Method::GET, "/ws", &headers, Body::empty())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "ws from {origin:?}");

        let mut headers = vec![("cookie", c.as_str()), ("content-type", "application/json")];
        if let Some(o) = origin {
            headers.push(("origin", o));
        }
        let r = send(request(
            Method::DELETE,
            "/api/profiles/x",
            &headers,
            Body::empty(),
        ))
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "delete from {origin:?}");
    }
    // The real page gets through the checks (to the 404 for a missing
    // connection, or the WebSocket handler).
    let r = send(request(
        Method::PUT,
        "/api/conn/99/upload?path=/tmp/x",
        &[("cookie", &c), ("origin", ORIGIN)],
        Body::from("x"),
    ))
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = send(request(
        Method::GET,
        "/api/conn/99/download?path=/tmp/x",
        &[("cookie", &c)],
        Body::empty(),
    ))
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let c = cookie();
    let requests = [
        request(Method::GET, "/", &[("cookie", &c)], Body::empty()),
        request(Method::GET, "/", &[], Body::empty()),
        request(Method::GET, "/assets/app.js", &[], Body::empty()),
        request(Method::GET, "/login?token=x", &[], Body::empty()),
        request(Method::GET, "/api/hosts", &[], Body::empty()),
    ];
    for req in requests {
        let uri = req.uri().to_string();
        let r = send(req).await;
        let h = r.headers();
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(
            csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"),
            "{uri}"
        );
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY", "{uri}");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer", "{uri}");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{uri}");
        assert_eq!(h[header::CACHE_CONTROL], "no-store", "{uri}");
    }
}

#[tokio::test]
async fn assets_are_served_and_nothing_else() {
    for (file, mime) in [
        ("app.js", "text/javascript"),
        ("app.css", "text/css"),
        ("xterm.js", "text/javascript"),
        ("icon.svg", "image/svg+xml"),
    ] {
        let r = send(request(
            Method::GET,
            &format!("/assets/{file}"),
            &[],
            Body::empty(),
        ))
        .await;
        assert_eq!(r.status(), StatusCode::OK, "{file}");
        assert!(r.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with(mime));
    }
    for file in ["index.html", "..%2FCargo.toml", "%2E%2E", "missing.js"] {
        let r = send(request(
            Method::GET,
            &format!("/assets/{file}"),
            &[],
            Body::empty(),
        ))
        .await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{file}");
    }
}

/// Every test that touches `$HOME` / `$XDG_CONFIG_HOME` lives here, so no
/// other test sees the changed environment.
#[tokio::test]
async fn profiles_and_hosts() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
    std::fs::write(
        home.path().join(".ssh/config"),
        "Host alpha\n  HostName 10.0.0.1\nHost *.wild\n  User x\nHost beta gamma\n  Port 2200\n",
    )
    .unwrap();
    std::env::set_var("HOME", home.path());
    std::env::set_var("XDG_CONFIG_HOME", home.path().join(".config"));
    let profiles_dir = home.path().join(".config/vortexssh/profiles");

    let app = app();
    let c = cookie();
    let call = |method: Method, uri: &str, body: Option<Value>| {
        let mut headers = vec![("cookie", c.as_str()), ("origin", ORIGIN)];
        let body = match body {
            Some(v) => {
                headers.push(("content-type", "application/json"));
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        router(app.clone()).oneshot(request(method, uri, &headers, body))
    };
    let json_of = |r: Response| async move {
        let status = r.status();
        let body = text(r).await;
        (
            status,
            serde_json::from_str::<Value>(&body).unwrap_or(Value::String(body)),
        )
    };

    // Empty store; aliases without wildcards.
    let (status, hosts) = json_of(call(Method::GET, "/api/hosts", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{hosts}");
    assert_eq!(hosts["profiles"], json!([]));
    assert_eq!(hosts["aliases"], json!(["alpha", "beta", "gamma"]));
    assert_eq!(hosts["errors"], json!([]));

    // Create.
    let form = json!({
        "name": "box", "target": "me@example.com", "port": 2222,
        "identity": "~/.ssh/id_test",
        "forwards": [{ "kind": "local", "spec": "8080:localhost:80" },
                     { "kind": "dynamic", "spec": "1080" }],
    });
    let (status, saved) = json_of(
        call(Method::POST, "/api/profiles", Some(form))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["user"], "me");
    assert_eq!(saved["host"], "example.com");
    assert_eq!(saved["port"], 2222);
    assert_eq!(saved["identity"], "~/.ssh/id_test");
    assert_eq!(saved["forwards"].as_array().unwrap().len(), 2);
    assert!(profiles_dir.join("box.toml").exists());

    // Invalid input is refused and nothing is written.
    let bad = [
        json!({ "name": "../evil", "target": "h" }),
        json!({ "name": "", "target": "h" }),
        json!({ "name": "ok2", "target": "" }),
        json!({ "name": "ok3", "target": "h", "forwards": [{ "kind": "local", "spec": "bogus" }] }),
        json!({ "name": "box", "target": "h" }), // already exists
    ];
    for form in bad {
        let (status, body) = json_of(
            call(Method::POST, "/api/profiles", Some(form.clone()))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{form} -> {body}");
    }
    let mut files: Vec<_> = std::fs::read_dir(&profiles_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files, ["box.toml"]);
    assert!(!home.path().join(".config/vortexssh/evil.toml").exists());

    // Rename keeps the settings and removes the old file.
    let form = json!({ "name": "box2", "target": "me@example.com", "port": 2222,
                       "forwards": [], "original": "box" });
    let (status, body) = json_of(
        call(Method::POST, "/api/profiles", Some(form))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!profiles_dir.join("box.toml").exists());
    let (_, hosts) = json_of(call(Method::GET, "/api/hosts", None).await.unwrap()).await;
    let names: Vec<_> = hosts["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].clone())
        .collect();
    assert_eq!(names, [json!("box2")]);

    // Delete, then deleting again or a bad name fails.
    let r = call(Method::DELETE, "/api/profiles/box2", None)
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(!profiles_dir.join("box2.toml").exists());
    for name in ["box2", "..%2Fx", "a%2Fb"] {
        let r = call(Method::DELETE, &format!("/api/profiles/{name}"), None)
            .await
            .unwrap();
        assert!(r.status().is_client_error(), "{name}: {}", r.status());
    }

    // A broken profile file is reported, not fatal.
    std::fs::write(profiles_dir.join("broken.toml"), "not = [valid").unwrap();
    let (status, hosts) = json_of(call(Method::GET, "/api/hosts", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hosts["errors"].as_array().unwrap().len(), 1, "{hosts}");
}
