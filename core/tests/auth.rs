//! Authentication flows against an in-process russh server.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use russh::server::{self, Auth, Response};
use russh::MethodKind;
use tokio::net::TcpListener;
use vortexssh_core::config::AuthMethod;
use vortexssh_core::keys::{generate, KeyKind};
use vortexssh_core::prompt::{KiPrompt, Prompter};
use vortexssh_core::ssh::{AcceptAll, Session};
use vortexssh_core::Error;

const PASSWORD: &str = "hunter2";
const OTP: &str = "123456";

/// Password, then OTP: the shape of a typical 2FA keyboard-interactive login.
#[derive(Default)]
struct TwoFactorServer {
    password_ok: bool,
}

impl server::Handler for TwoFactorServer {
    type Error = russh::Error;

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut methods = russh::MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::KeyboardInteractive);
    let config = Arc::new(server::Config {
        keys: vec![generate(KeyKind::Ed25519, "").unwrap()],
        methods,
        auth_rejection_time: std::time::Duration::ZERO,
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        if let Ok(session) = server::run_stream(config, socket, TwoFactorServer::default()).await {
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
    Session::connect("127.0.0.1", port, "alice", &auth, prompter, Arc::new(AcceptAll)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_two_rounds() {
    let p = Scripted::new(&[Some(PASSWORD), Some(OTP)]);
    connect(AuthMethod::KeyboardInteractive, p.clone()).await.unwrap();
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
    let err = connect(AuthMethod::KeyboardInteractive, p).await.err().unwrap();
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
    let err = connect(AuthMethod::Password, p.clone()).await.err().unwrap();
    assert!(matches!(err, Error::AuthFailed { .. }), "{err}");
    assert_eq!(p.asked().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_prompt_aborts() {
    let p = Scripted::new(&[None]);
    let err = connect(AuthMethod::Password, p).await.err().unwrap();
    assert!(matches!(err, Error::Cancelled), "{err}");
}
