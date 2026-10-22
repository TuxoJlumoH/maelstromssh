//! Authentication flows against an in-process russh server.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use russh::keys::PublicKey;
use russh::server::{self, Auth, Response};
use russh::MethodKind;
use tokio::net::TcpListener;
use vortexssh_core::config::AuthMethod;
use vortexssh_core::keys::{generate, save_openssh, KeyKind};
use vortexssh_core::prompt::{KiPrompt, Prompter};
use vortexssh_core::ssh::{AcceptAll, Session};
use vortexssh_core::Error;

const PASSWORD: &str = "hunter2";
const OTP: &str = "123456";

/// Password, then OTP: the shape of a typical 2FA keyboard-interactive login.
/// Also accepts one public key, when configured.
#[derive(Default)]
struct TwoFactorServer {
    password_ok: bool,
    authorized: Option<PublicKey>,
}

impl server::Handler for TwoFactorServer {
    type Error = russh::Error;

    // Like sshd, only acknowledge (PK_OK) keys that are authorized.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_publickey(user, key).await
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(match &self.authorized {
            Some(k) if k.key_data() == key.key_data() => Auth::Accept,
            _ => Auth::reject(),
        })
    }

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let answer = response.and_then(|mut r| r.next());
        let partial = |prompt: &'static str, echo: bool| Auth::Partial {
            name: Cow::Borrowed("2FA"),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(vec![(Cow::Borrowed(prompt), echo)]),
        };
        Ok(match (self.password_ok, answer) {
            (false, None) => partial("Password: ", false),
            (false, Some(a)) if &a[..] == PASSWORD.as_bytes() => {
                self.password_ok = true;
                partial("Verification code: ", true)
            }
            (true, Some(a)) if &a[..] == OTP.as_bytes() => Auth::Accept,
            _ => Auth::reject(),
        })
    }
}

/// Starts a one-connection server and returns its port.
async fn serve_once() -> u16 {
    serve(
        &[MethodKind::Password, MethodKind::KeyboardInteractive],
        None,
    )
    .await
}

async fn serve(offered: &[MethodKind], authorized: Option<PublicKey>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let methods = russh::MethodSet::from(offered);
    let config = Arc::new(server::Config {
        keys: vec![generate(KeyKind::Ed25519, "").unwrap()],
        methods,
        auth_rejection_time: std::time::Duration::ZERO,
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let handler = TwoFactorServer {
            authorized,
            ..Default::default()
        };
        if let Ok(session) = server::run_stream(config, socket, handler).await {
            let _ = session.await;
        }
    });
    port
}

/// Answers prompts from a script and records what it was asked.
#[derive(Default)]
struct Scripted {
    answers: Mutex<VecDeque<Option<String>>>,
    asked: Mutex<Vec<(String, bool)>>,
}

impl Scripted {
    fn new(answers: &[Option<&str>]) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.iter().map(|a| a.map(String::from)).collect()),
            asked: Mutex::default(),
        })
    }

    fn next(&self) -> Option<String> {
        self.answers.lock().unwrap().pop_front().flatten()
    }

    fn asked(&self) -> Vec<(String, bool)> {
        self.asked.lock().unwrap().clone()
    }
}

impl Prompter for Scripted {
    fn secret(&self, prompt: &str) -> Option<String> {
        self.asked.lock().unwrap().push((prompt.to_string(), false));
        self.next()
    }

    fn confirm_host_key(&self, _: &str, _: u16, _: &str) -> bool {
        unreachable!("tests use AcceptAll")
    }

    fn keyboard_interactive(&self, _: &str, _: &str, prompts: &[KiPrompt]) -> Option<Vec<String>> {
        let mut asked = self.asked.lock().unwrap();
        prompts
            .iter()
            .map(|p| {
                asked.push((p.text.clone(), p.echo));
                self.next()
            })
            .collect()
    }
}

async fn connect(auth: AuthMethod, prompter: Arc<Scripted>) -> vortexssh_core::Result<Session> {
    let port = serve_once().await;
    Session::connect(
        "127.0.0.1",
        port,
        "alice",
        &auth,
        prompter,
        Arc::new(AcceptAll),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_two_rounds() {
    let p = Scripted::new(&[Some(PASSWORD), Some(OTP)]);
    connect(AuthMethod::KeyboardInteractive, p.clone())
        .await
        .unwrap();
    assert_eq!(
        p.asked(),
        vec![
            ("Password: ".to_string(), false),
            ("Verification code: ".to_string(), true)
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_wrong_code_fails() {
    let p = Scripted::new(&[Some(PASSWORD), Some("000000")]);
    let err = connect(AuthMethod::KeyboardInteractive, p)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::AuthFailed { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn password_retries_after_typo() {
    let p = Scripted::new(&[Some("typo"), Some(PASSWORD)]);
    connect(AuthMethod::Password, p.clone()).await.unwrap();
    assert_eq!(p.asked().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn password_gives_up_after_three_attempts() {
    let p = Scripted::new(&[Some("a"), Some("b"), Some("c"), Some(PASSWORD)]);
    let err = connect(AuthMethod::Password, p.clone())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::AuthFailed { .. }), "{err}");
    assert_eq!(p.asked().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_prompt_aborts() {
    let p = Scripted::new(&[None]);
    let err = connect(AuthMethod::Password, p).await.err().unwrap();
    assert!(matches!(err, Error::Cancelled), "{err}");
}

/// Writes a fresh key to a temp file; returns its path and public key.
fn key_file(name: &str, passphrase: Option<&str>) -> (std::path::PathBuf, PublicKey) {
    let dir = std::env::temp_dir().join(format!("vortexssh-auth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let key = generate(KeyKind::Ed25519, "").unwrap();
    let public = key.public_key().clone();
    let key = match passphrase {
        Some(p) => key
            .encrypt(
                &mut russh::keys::ssh_key::rand_core::UnwrapErr(
                    russh::keys::ssh_key::getrandom::SysRng,
                ),
                p,
            )
            .unwrap(),
        None => key,
    };
    save_openssh(&key, &path).unwrap();
    (path, public)
}

fn auto(identities: &[&std::path::Path]) -> AuthMethod {
    AuthMethod::Auto {
        identities: identities.iter().map(|p| p.display().to_string()).collect(),
    }
}

async fn connect_to(
    port: u16,
    auth: AuthMethod,
    prompter: Arc<Scripted>,
) -> vortexssh_core::Result<Session> {
    Session::connect(
        "127.0.0.1",
        port,
        "alice",
        &auth,
        prompter,
        Arc::new(AcceptAll),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_uses_key_without_prompting() {
    let (path, public) = key_file("plain", None);
    let port = serve(&[MethodKind::PublicKey, MethodKind::Password], Some(public)).await;
    let p = Scripted::new(&[]);
    connect_to(port, auto(&[&path]), p.clone()).await.unwrap();
    assert!(p.asked().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_asks_passphrase_only_for_accepted_key() {
    let (rejected, _) = key_file("other_enc", Some("nope"));
    let (accepted, public) = key_file("enc", Some("pw"));
    let port = serve(&[MethodKind::PublicKey], Some(public)).await;
    let p = Scripted::new(&[Some("typo"), Some("pw")]);
    connect_to(port, auto(&[&rejected, &accepted]), p.clone())
        .await
        .unwrap();
    let asked: Vec<String> = p.asked().into_iter().map(|(q, _)| q).collect();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert!(
        asked
            .iter()
            .all(|q| q.contains("enc") && !q.contains("other")),
        "{asked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_falls_back_to_password() {
    let (path, _) = key_file("unauthorized", None);
    let port = serve(&[MethodKind::PublicKey, MethodKind::Password], None).await;
    let p = Scripted::new(&[Some(PASSWORD)]);
    connect_to(port, auto(&[&path]), p.clone()).await.unwrap();
    assert_eq!(p.asked().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_prefers_keyboard_interactive_when_offered() {
    let p = Scripted::new(&[Some(PASSWORD), Some(OTP)]);
    let port = serve_once().await;
    connect_to(port, auto(&[]), p.clone()).await.unwrap();
    assert_eq!(p.asked()[1].0, "Verification code: ");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_failure_lists_what_was_tried() {
    let (path, _) = key_file("nobody", None);
    let port = serve(&[MethodKind::PublicKey], None).await;
    let err = connect_to(port, auto(&[&path]), Scripted::new(&[]))
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        err.contains("nobody") && err.contains("server accepts: publickey"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_key_file_fails_before_connecting() {
    let err = connect_to(
        1,
        auto(&[std::path::Path::new("/no/such/key")]),
        Scripted::new(&[]),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("/no/such/key not found"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_passphrase_skips_key_and_falls_back() {
    let (path, public) = key_file("enc_skip", Some("pw"));
    let port = serve(&[MethodKind::PublicKey, MethodKind::Password], Some(public)).await;
    let p = Scripted::new(&[Some(""), Some(PASSWORD)]);
    connect_to(port, auto(&[&path]), p.clone()).await.unwrap();
    let asked: Vec<String> = p.asked().into_iter().map(|(q, _)| q).collect();
    assert!(
        asked[0].starts_with("Passphrase for") && asked[1].contains("password"),
        "{asked:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_passphrases_skip_key_and_fall_back() {
    let (path, public) = key_file("enc_wrong", Some("pw"));
    let port = serve(&[MethodKind::PublicKey, MethodKind::Password], Some(public)).await;
    let p = Scripted::new(&[Some("a"), Some("b"), Some("c"), Some(PASSWORD)]);
    connect_to(port, auto(&[&path]), p.clone()).await.unwrap();
    assert_eq!(p.asked().len(), 4);
}
