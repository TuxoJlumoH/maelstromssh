//! Plain HTTP endpoints: the host list, saving and deleting profiles, and
//! streaming file downloads and uploads over an open connection.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio_util::io::{ReaderStream, StreamReader};
use vortexssh_core::config::{
    check_profile_name, parse_forward, AuthMethod, ForwardKind, Profile, ProfileStore, SshConfig,
};
use vortexssh_core::sftp;
use vortexssh_core::target::{local_user, split_target};

use crate::App;

type ApiResult<T> = Result<T, (StatusCode, String)>;

fn bad_request(e: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}

fn server_error(e: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn store() -> ApiResult<ProfileStore> {
    ProfileStore::default_location().map_err(server_error)
}

/// Runs blocking file work (profiles, ssh_config) off the async workers.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> ApiResult<T> + Send + 'static,
) -> ApiResult<T> {
    tokio::task::spawn_blocking(f).await.map_err(server_error)?
}

/// `GET /api/hosts`: saved profiles and `~/.ssh/config` aliases.
pub async fn hosts() -> ApiResult<Json<Value>> {
    blocking(|| {
        let store = store()?;
        let mut profiles = Vec::new();
        let mut errors = Vec::new();
        for name in store.list().map_err(server_error)? {
            match store.load(&name) {
                Ok(p) => profiles.push(profile_json(&p)),
                Err(e) => errors.push(e.to_string()),
            }
        }
        let aliases = match SshConfig::load_user() {
            Ok(c) => c.host_aliases(),
            Err(e) => {
                errors.push(e.to_string());
                Vec::new()
            }
        };
        Ok(Json(json!({
            "profiles": profiles,
            "aliases": aliases,
            "user": local_user(),
            "errors": errors,
        })))
    })
    .await
}

fn profile_json(p: &Profile) -> Value {
    let identity = match &p.auth {
        AuthMethod::Auto { identities } => identities.first().cloned(),
        AuthMethod::PublicKey { key_path } => Some(key_path.clone()),
        _ => None,
    };
    let auth = match &p.auth {
        AuthMethod::Auto { .. } => "auto",
        AuthMethod::Password => "password",
        AuthMethod::PublicKey { .. } => "key",
        AuthMethod::Agent => "agent",
        AuthMethod::KeyboardInteractive => "keyboard-interactive",
    };
    let forwards: Vec<Value> = p
        .forwards
        .iter()
        .map(|f| json!({ "kind": f.kind, "spec": vortexssh_core::config::forward_spec(f) }))
        .collect();
    json!({
        "name": p.name, "host": p.host, "port": p.port, "user": p.user,
        "auth": auth, "identity": identity, "forwards": forwards,
    })
}

#[derive(Deserialize)]
pub struct ProfileForm {
    name: String,
    /// `user@host` or `host`.
    target: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    forwards: Vec<ForwardForm>,
    /// The name being edited, when renaming.
    #[serde(default)]
    original: Option<String>,
}

#[derive(Deserialize)]
pub struct ForwardForm {
    kind: ForwardKind,
    spec: String,
}

/// `POST /api/profiles`: create or update a profile.
pub async fn save_profile(Json(form): Json<ProfileForm>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let name = form.name.trim().to_string();
        check_profile_name(&name).map_err(bad_request)?;
        let (user, host) = split_target(form.target.trim());
        if host.is_empty() {
            return Err(bad_request("enter a host"));
        }
        let forwards = form
            .forwards
            .iter()
            .filter(|f| !f.spec.trim().is_empty())
            .map(|f| parse_forward(f.spec.trim(), f.kind))
            .collect::<Result<Vec<_>, _>>()
            .map_err(bad_request)?;
        let identities = form
            .identity
            .map(|i| i.trim().to_string())
            .filter(|i| !i.is_empty())
            .into_iter()
            .collect();

        let store = store()?;
        // Keep settings the form does not show (terminal, a fixed auth
        // method) when editing.
        let source = form.original.as_deref().unwrap_or(&name);
        let existing = store.load(source).ok();
        let auth = match existing.as_ref().map(|p| &p.auth) {
            Some(AuthMethod::Auto { .. }) | None => AuthMethod::Auto { identities },
            Some(AuthMethod::PublicKey { .. }) if !identities.is_empty() => AuthMethod::PublicKey {
                key_path: identities[0].clone(),
            },
            Some(other) => other.clone(),
        };
        if form.original.as_deref() != Some(name.as_str()) && store.load(&name).is_ok() {
            return Err(bad_request(format!(
                "a profile named '{name}' already exists"
            )));
        }
        let profile = Profile {
            name: name.clone(),
            host,
            port: form.port.unwrap_or(22),
            user: user.unwrap_or_else(local_user),
            auth,
            forwards,
            terminal: existing.map(|p| p.terminal).unwrap_or_default(),
        };
        store.save(&profile).map_err(server_error)?;
        if let Some(original) = form.original.filter(|o| *o != name) {
            let _ = store.delete(&original);
        }
        Ok(Json(profile_json(&profile)))
    })
    .await
}

/// `DELETE /api/profiles/{name}`.
pub async fn delete_profile(Path(name): Path<String>) -> ApiResult<StatusCode> {
    blocking(move || {
        check_profile_name(&name).map_err(bad_request)?;
        store()?.delete(&name).map_err(bad_request)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

#[derive(Deserialize)]
pub struct FilePath {
    path: String,
}

/// How long a download ticket can wait for the browser to use it.
const TICKET_LIFETIME: Duration = Duration::from_secs(60);

/// A one-time permission to download `path` over connection `conn`.
pub struct Ticket {
    pub(crate) conn: u64,
    pub(crate) path: String,
    pub(crate) expires: Instant,
}

#[derive(Deserialize)]
pub struct TicketRequest {
    path: String,
}

/// `POST /api/conn/{id}/download`: checks that `path` is a readable file
/// and returns a one-time ticket for `GET /download/{ticket}`. Downloads are
/// started by the browser itself (so they stream to disk), and it can't add
/// the token header to those requests.
pub async fn download_ticket(
    State(app): State<Arc<App>>,
    Path(id): Path<u64>,
    Json(q): Json<TicketRequest>,
) -> ApiResult<Json<Value>> {
    let conn = app
        .conn(id)
        .ok_or((StatusCode::NOT_FOUND, "connection closed".into()))?;
    let sftp = conn.sftp().await.map_err(server_error)?;
    // Catch errors here, where the page can show them; the browser's
    // download list would only say "failed".
    drop(sftp::open_read(sftp, &q.path).await.map_err(bad_request)?);
    let ticket = crate::auth::new_token().map_err(server_error)?;
    let now = Instant::now();
    let mut tickets = app.tickets.lock().unwrap_or_else(|p| p.into_inner());
    tickets.retain(|_, t| t.expires > now);
    tickets.insert(
        ticket.clone(),
        Ticket {
            conn: id,
            path: q.path,
            expires: now + TICKET_LIFETIME,
        },
    );
    Ok(Json(json!({ "ticket": ticket })))
}

/// `GET /download/{ticket}`: streams the remote file a ticket allows.
pub async fn download(
    State(app): State<Arc<App>>,
    Path(ticket): Path<String>,
) -> ApiResult<Response> {
    let gone = || {
        (
            StatusCode::NOT_FOUND,
            "this download link has expired".to_string(),
        )
    };
    let ticket = app
        .tickets
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&ticket)
        .filter(|t| t.expires > Instant::now())
        .ok_or_else(gone)?;
    let conn = app
        .conn(ticket.conn)
        .ok_or((StatusCode::NOT_FOUND, "connection closed".into()))?;
    let path = ticket.path;
    let sftp = conn.sftp().await.map_err(server_error)?;
    let size = sftp::file_size(sftp, &path).await.map_err(bad_request)?;
    let file = sftp::open_read(sftp, &path).await.map_err(bad_request)?;

    let name = path.rsplit('/').next().unwrap_or("download");
    let mut response =
        Body::from_stream(ReaderStream::with_capacity(file, 64 * 1024)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&content_disposition(name)) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(size) = size {
        headers.insert(header::CONTENT_LENGTH, size.into());
    }
    Ok(response)
}

/// `attachment` with an ASCII fallback and the exact UTF-8 name (RFC 6266).
fn content_disposition(name: &str) -> String {
    let fallback: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

/// `PUT /api/conn/{id}/upload?path=…`: streams the request body into a
/// remote file (created or replaced).
///
/// The data goes to a temporary file next to the target, which replaces the
/// target only once the whole body has arrived, so a cancelled or failed
/// upload never leaves a truncated file behind.
pub async fn upload(
    State(app): State<Arc<App>>,
    Path(id): Path<u64>,
    Query(q): Query<FilePath>,
    body: Body,
) -> ApiResult<Json<Value>> {
    let conn = app
        .conn(id)
        .ok_or((StatusCode::NOT_FOUND, "connection closed".into()))?;
    let sftp = conn.sftp().await.map_err(server_error)?;
    // Write next to the file a symlink points to, so the final rename stays
    // in one folder and file system.
    let dest = sftp::resolve_link(sftp, &q.path)
        .await
        .map_err(bad_request)?;
    let temp = temp_upload_path(&dest).map_err(bad_request)?;
    let mut file = sftp::open_write(sftp, &temp).await.map_err(bad_request)?;
    // Removes the temporary file unless the upload completes, also when the
    // browser goes away and this handler is dropped mid-upload.
    let mut guard = TempGuard {
        conn: Some(conn.clone()),
        path: temp.clone(),
    };
    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let mut reader = StreamReader::new(stream);
    let copied = async {
        let written = tokio::io::copy(&mut reader, &mut file).await?;
        file.shutdown().await?;
        Ok::<_, std::io::Error>(written)
    }
    .await;
    drop(file);
    let written = match copied {
        Ok(written) => written,
        Err(e) => return Err(server_error(format!("upload interrupted: {e}"))),
    };
    sftp::replace(sftp, &temp, &dest)
        .await
        .map_err(bad_request)?;
    guard.conn = None;
    Ok(Json(json!({ "written": written })))
}

struct TempGuard {
    conn: Option<Arc<crate::conn::Conn>>,
    path: String,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        let path = std::mem::take(&mut self.path);
        tokio::spawn(async move {
            if let Ok(sftp) = conn.sftp().await {
                let _ = sftp::remove_file(sftp, &path).await;
            }
        });
    }
}

/// The longest part of the original name kept in a temporary name.
const MAX_TEMP_STEM: usize = 200;

/// A hidden, unique name in the same folder as `path` (so the final rename
/// stays on one file system).
fn temp_upload_path(path: &str) -> Result<String, String> {
    let (dir, name) = match path.rsplit_once('/') {
        Some((dir, name)) => (dir, name),
        None => ("", path),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("'{path}' is not a file name"));
    }
    let mut suffix = [0u8; 6];
    getrandom::fill(&mut suffix).map_err(|e| e.to_string())?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    // Keep the temporary name (and its ".old" backup) under the usual
    // 255-byte limit for file names.
    let mut end = name.len().min(MAX_TEMP_STEM);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let temp = format!(".{}.vortexssh-{suffix}.part", &name[..end]);
    Ok(if path.contains('/') {
        format!("{dir}/{temp}")
    } else {
        temp
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_disposition_escapes_names() {
        assert_eq!(
            content_disposition("a b\".txt"),
            "attachment; filename=\"a_b_.txt\"; filename*=UTF-8''a%20b%22.txt"
        );
        assert!(content_disposition("файл.txt").contains("filename*=UTF-8''%D1%84"));
    }

    #[test]
    fn temp_upload_paths_stay_in_the_folder() {
        let temp = temp_upload_path("/home/me/a.txt").unwrap();
        assert!(temp.starts_with("/home/me/.a.txt.vortexssh-"), "{temp}");
        assert!(temp.ends_with(".part"));
        assert_ne!(temp, temp_upload_path("/home/me/a.txt").unwrap());
        assert!(temp_upload_path("a.txt").unwrap().starts_with(".a.txt."));
        assert!(temp_upload_path("/top").unwrap().starts_with("/.top."));
        let long = format!("/d/{}", "ü".repeat(127)); // 254 bytes
        let temp = temp_upload_path(&long).unwrap();
        let name = temp.rsplit_once('/').unwrap().1;
        assert!(name.len() + ".old".len() <= 255, "{}", name.len());
        assert!(name.starts_with(".üü"));
        for bad in ["/home/me/", "", "/x/..", "."] {
            assert!(temp_upload_path(bad).is_err(), "{bad:?}");
        }
    }
}
