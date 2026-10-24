//! Router tests: access control, security headers, assets and the profile
//! API, run against the real router without a network socket.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::api::Ticket;
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
        tickets: Mutex::new(HashMap::new()),
    })
}

fn bearer() -> String {
    format!("Bearer {}", "a".repeat(64))
}

/// The headers of a WebSocket upgrade, offering `protocols`.
fn ws_headers(protocols: &str) -> Vec<(&str, &str)> {
    vec![
        ("upgrade", "websocket"),
        ("connection", "upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("sec-websocket-protocol", protocols),
    ]
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
async fn the_page_is_public_and_sets_no_cookie() {
    let r = send(request(Method::GET, "/", &[], Body::empty())).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(!r.headers().contains_key(header::SET_COOKIE));
    assert!(text(r).await.contains("/assets/app.js"));

    for uri in ["/login", "/login?token=x"] {
        let r = send(request(Method::GET, uri, &[], Body::empty())).await;
        assert!(r.status().is_client_error(), "{uri}");
        assert!(!r.headers().contains_key(header::SET_COOKIE), "{uri}");
    }
}

#[tokio::test]
async fn api_routes_need_the_token() {
    let routes = [
        (Method::GET, "/api/hosts"),
        (Method::GET, "/api/serial-ports"),
        (Method::POST, "/api/profiles"),
        (Method::DELETE, "/api/profiles/x"),
        (Method::POST, "/api/conn/1/download"),
        (Method::PUT, "/api/conn/1/upload?path=/tmp/x"),
        (Method::GET, "/ws"),
    ];
    let wrong = format!("Bearer {}", "b".repeat(64));
    let short = format!("Bearer {}", "a".repeat(63));
    let bare = "a".repeat(64);
    // A cookie is not enough any more, whatever its name.
    let cookie = format!("maelstromssh_{PORT}={}", "a".repeat(64));
    for (method, uri) in routes {
        for auth in [
            None,
            Some(wrong.as_str()),
            Some(short.as_str()),
            Some(bare.as_str()),
        ] {
            let mut headers = vec![("origin", ORIGIN), ("cookie", cookie.as_str())];
            if let Some(a) = auth {
                headers.push(("authorization", a));
            }
            let r = send(request(method.clone(), uri, &headers, Body::empty())).await;
            assert_eq!(
                r.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} {auth:?}"
            );
        }
    }
    let b = bearer();
    let r = send(request(
        Method::GET,
        "/api/hosts",
        &[("authorization", &b), ("origin", "http://evil.example")],
        Body::empty(),
    ))
    .await;
    // GETs change nothing, so they don't need an Origin; this one only
    // fails if the token check let it through and the handler errored.
    assert_ne!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn websockets_take_the_token_as_a_subprotocol() {
    let token = format!("token-{}", "a".repeat(64));
    let good = format!("maelstromssh, {token}");
    let wrong = format!("maelstromssh, token-{}", "b".repeat(64));
    // Without a real connection to upgrade, a request that passes the
    // checks gets 426 from the WebSocket handler.
    for (protocols, expected) in [
        (good.as_str(), StatusCode::UPGRADE_REQUIRED),
        (wrong.as_str(), StatusCode::UNAUTHORIZED),
        ("maelstromssh", StatusCode::UNAUTHORIZED),
    ] {
        let mut headers = ws_headers(protocols);
        headers.push(("origin", ORIGIN));
        let r = send(request(Method::GET, "/ws", &headers, Body::empty())).await;
        assert_eq!(r.status(), expected, "{protocols}");
    }
}

#[tokio::test]
async fn foreign_hosts_are_refused() {
    // DNS rebinding: a page on evil.example resolving to 127.0.0.1.
    for host in ["evil.example:18999", "127.0.0.1:8022", "127.0.0.1", ""] {
        for uri in ["/", "/api/hosts", "/download/x"] {
            let req = Request::builder()
                .uri(uri)
                .header(header::HOST, host)
                .header(header::AUTHORIZATION, bearer())
                .body(Body::empty())
                .unwrap();
            let r = send(req).await;
            assert_eq!(
                r.status(),
                StatusCode::MISDIRECTED_REQUEST,
                "{host:?} {uri}"
            );
        }
    }
    let req = Request::builder()
        .uri("/")
        .header(header::HOST, "localhost:18999")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(req).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn changes_and_websockets_need_this_origin() {
    let b = bearer();
    let token = format!("maelstromssh, token-{}", "a".repeat(64));
    for origin in [
        None,
        Some("http://evil.example"),
        Some("http://127.0.0.1:8022"),
        Some("null"),
    ] {
        let mut headers = ws_headers(&token);
        if let Some(o) = origin {
            headers.push(("origin", o));
        }
        let r = send(request(Method::GET, "/ws", &headers, Body::empty())).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "ws from {origin:?}");

        let mut headers = vec![("authorization", b.as_str())];
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
    // connection).
    let r = send(request(
        Method::PUT,
        "/api/conn/99/upload?path=/tmp/x",
        &[("authorization", &b), ("origin", ORIGIN)],
        Body::from("x"),
    ))
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = send(request(
        Method::POST,
        "/api/conn/99/download",
        &[
            ("authorization", &b),
            ("origin", ORIGIN),
            ("content-type", "application/json"),
        ],
        Body::from(r#"{"path":"/tmp/x"}"#),
    ))
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_tickets_are_one_time_and_expire() {
    let app = app();
    let get = |ticket: &str| {
        router(app.clone()).oneshot(request(
            Method::GET,
            &format!("/download/{ticket}"),
            &[],
            Body::empty(),
        ))
    };
    let now = Instant::now();
    {
        let mut tickets = app.tickets.lock().unwrap();
        for (name, expires) in [("fresh", now + Duration::from_secs(60)), ("old", now)] {
            tickets.insert(
                name.to_string(),
                Ticket {
                    conn: 99,
                    path: "/tmp/x".into(),
                    expires,
                },
            );
        }
    }
    // The ticket is accepted (connection 99 doesn't exist) and used up.
    let r = get("fresh").await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert!(text(r).await.contains("connection closed"));
    for ticket in ["fresh", "old", "unknown"] {
        let r = get(ticket).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{ticket}");
        assert!(text(r).await.contains("expired"), "{ticket}");
    }
}

#[tokio::test]
async fn security_headers_on_every_response() {
    let b = bearer();
    let requests = [
        request(Method::GET, "/", &[], Body::empty()),
        request(Method::GET, "/assets/app.js", &[], Body::empty()),
        request(Method::GET, "/api/hosts", &[], Body::empty()),
        request(
            Method::GET,
            "/api/hosts",
            &[("authorization", &b)],
            Body::empty(),
        ),
        request(Method::GET, "/download/x", &[], Body::empty()),
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
    let profiles_dir = home.path().join(".config/maelstromssh/profiles");

    let app = app();
    let b = bearer();
    let call = |method: Method, uri: &str, body: Option<Value>| {
        let mut headers = vec![("authorization", b.as_str()), ("origin", ORIGIN)];
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
    assert!(!home.path().join(".config/maelstromssh/evil.toml").exists());

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

    // Serial profiles: saved with their line settings, listed with them,
    // and refused with bad settings.
    let form = json!({ "name": "console", "target": "/dev/ttyUSB0",
                       "serial": { "baud": 115200, "parity": "even" } });
    let (status, saved) = json_of(
        call(Method::POST, "/api/profiles", Some(form))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["protocol"], "serial");
    assert_eq!(saved["device"], "/dev/ttyUSB0");
    assert_eq!(saved["line"], "115200 8E1");
    assert_eq!(saved["serial"]["flow_control"], "none");
    for form in [
        json!({ "name": "s2", "target": "", "serial": {} }),
        json!({ "name": "s3", "target": "/dev/ttyS0", "serial": { "data_bits": 9 } }),
        json!({ "name": "s4", "target": "/dev/ttyS0", "serial": { "parity": "mark" } }),
    ] {
        let (status, body) = json_of(
            call(Method::POST, "/api/profiles", Some(form.clone()))
                .await
                .unwrap(),
        )
        .await;
        assert!(status.is_client_error(), "{form} -> {status} {body}");
    }
    let (_, hosts) = json_of(call(Method::GET, "/api/hosts", None).await.unwrap()).await;
    assert_eq!(hosts["profiles"][0]["protocol"], "serial", "{hosts}");
    let r = call(Method::DELETE, "/api/profiles/console", None)
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    // Telnet and raw profiles: Telnet defaults to port 23, raw needs one.
    let form = json!({ "name": "sw", "protocol": "telnet", "target": "switch.lan" });
    let (status, saved) = json_of(
        call(Method::POST, "/api/profiles", Some(form))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        saved,
        json!({ "name": "sw", "protocol": "telnet", "host": "switch.lan", "port": 23 })
    );
    let form = json!({ "name": "sw", "original": "sw", "protocol": "raw", "target": "10.0.0.2", "port": 4001 });
    let (status, saved) = json_of(
        call(Method::POST, "/api/profiles", Some(form))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["protocol"], "raw");
    assert_eq!(saved["port"], 4001);
    for form in [
        json!({ "name": "r2", "protocol": "raw", "target": "10.0.0.2" }),
        json!({ "name": "r3", "protocol": "telnet", "target": "" }),
        json!({ "name": "r4", "protocol": "telnet", "target": "root@box" }),
        json!({ "name": "r5", "protocol": "gopher", "target": "box" }),
    ] {
        let (status, body) = json_of(
            call(Method::POST, "/api/profiles", Some(form.clone()))
                .await
                .unwrap(),
        )
        .await;
        assert!(status.is_client_error(), "{form} -> {status} {body}");
    }
    let r = call(Method::DELETE, "/api/profiles/sw", None)
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);

    let (status, ports) =
        json_of(call(Method::GET, "/api/serial-ports", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{ports}");
    assert!(ports.is_array());

    // A broken profile file is reported, not fatal.
    std::fs::write(profiles_dir.join("broken.toml"), "not = [valid").unwrap();
    let (status, hosts) = json_of(call(Method::GET, "/api/hosts", None).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hosts["errors"].as_array().unwrap().len(), 1, "{hosts}");
}
