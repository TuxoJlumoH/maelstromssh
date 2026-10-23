//! The browser app, built into the binary so there is nothing to install
//! next to it.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

const INDEX: &str = include_str!("../assets/index.html");

const FILES: &[(&str, &str, &[u8])] = &[
    (
        "app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/app.js"),
    ),
    (
        "app.css",
        "text/css; charset=utf-8",
        include_bytes!("../assets/app.css"),
    ),
    (
        "icon.svg",
        "image/svg+xml",
        include_bytes!("../assets/icon.svg"),
    ),
    (
        "xterm.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/vendor/xterm.js"),
    ),
    (
        "xterm.css",
        "text/css; charset=utf-8",
        include_bytes!("../assets/vendor/xterm.css"),
    ),
    (
        "addon-fit.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../assets/vendor/addon-fit.js"),
    ),
];

pub fn index() -> Response {
    Html(INDEX).into_response()
}

/// `GET /assets/{file}`: public, so the login error page can be styled.
pub async fn serve(Path(file): Path<String>) -> Response {
    match FILES.iter().find(|(name, _, _)| *name == file) {
        Some((_, mime, body)) => ([(header::CONTENT_TYPE, *mime)], *body).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
