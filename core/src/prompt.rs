//! Interactive questions asked while a connection is being set up: secrets
//! (passwords, key passphrases), unknown host keys, and keyboard-interactive
//! (2FA/OTP) challenges. Each front-end supplies its own [`Prompter`]; the
//! CLI and TUI share [`TtyPrompter`] (behind the `tty` feature).
//!
//! Prompters are called from inside the async connect task and may block
//! (reading stdin, waiting on a GUI dialog), so sessions must run on a
//! multi-threaded tokio runtime.

/// One prompt in a keyboard-interactive challenge.
#[derive(Debug, Clone)]
pub struct KiPrompt {
    pub text: String,
    /// Whether the answer may be shown as it is typed (e.g. a username),
    /// as opposed to a hidden secret (a password or OTP code).
    pub echo: bool,
}

pub trait Prompter: Send + Sync {
    /// Asks for a hidden secret. `None` means the user cancelled.
    fn secret(&self, prompt: &str) -> Option<String>;

    /// Asks whether to trust an unknown host key.
    fn confirm_host_key(&self, host: &str, port: u16, fingerprint: &str) -> bool;

    /// Answers a keyboard-interactive challenge, one response per prompt.
    /// `None` means the user cancelled.
    fn keyboard_interactive(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[KiPrompt],
    ) -> Option<Vec<String>>;
}

/// Answers nothing: secrets and challenges are cancelled and unknown host
/// keys are rejected. For non-interactive use (scripts, smoke tests).
pub struct NoPrompt;

impl Prompter for NoPrompt {
    fn secret(&self, _prompt: &str) -> Option<String> {
        None
    }

    fn confirm_host_key(&self, _host: &str, _port: u16, _fingerprint: &str) -> bool {
        false
    }

    fn keyboard_interactive(&self, _: &str, _: &str, _: &[KiPrompt]) -> Option<Vec<String>> {
        None
    }
}

#[cfg(feature = "tty")]
pub use tty::TtyPrompter;

#[cfg(feature = "tty")]
mod tty {
    use std::io::{BufRead, Write};

    use super::{KiPrompt, Prompter};

    /// Prompts on the controlling terminal: hidden input for secrets, a
    /// `yes/no` question for host keys.
    pub struct TtyPrompter;

    fn read_line(prompt: &str) -> Option<String> {
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
        }
    }

    impl Prompter for TtyPrompter {
        fn secret(&self, prompt: &str) -> Option<String> {
            rpassword::prompt_password(prompt).ok()
        }

        fn confirm_host_key(&self, host: &str, port: u16, fingerprint: &str) -> bool {
            eprintln!(
                "The authenticity of host '{host}:{port}' can't be established.\n\
                 Key fingerprint is {fingerprint}."
            );
            loop {
                let Some(answer) = read_line("Continue connecting (yes/no)? ") else {
                    return false;
                };
                match answer.trim().to_ascii_lowercase().as_str() {
                    "yes" => return true,
                    "no" => return false,
                    _ => eprintln!("Please type 'yes' or 'no'."),
                }
            }
        }

        fn keyboard_interactive(
            &self,
            name: &str,
            instructions: &str,
            prompts: &[KiPrompt],
        ) -> Option<Vec<String>> {
            if !name.is_empty() {
                eprintln!("{name}");
            }
            if !instructions.is_empty() {
                eprintln!("{instructions}");
            }
            prompts
                .iter()
                .map(|p| {
                    if p.echo {
                        read_line(&p.text)
                    } else {
                        self.secret(&p.text)
                    }
                })
                .collect()
        }
    }
}
