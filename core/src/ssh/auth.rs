//! Client authentication. Each method has its own step; `auto` chains them
//! the way OpenSSH does: agent keys, then key files, then
//! keyboard-interactive or password, whichever the server offers.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::AgentIdentity;
use russh::keys::signature::Signer as _;
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::ssh_key::{self as ssh_key, Algorithm, Signature};
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::{MethodKind, MethodSet};

use crate::config::AuthMethod;
use crate::error::{Error, Result};
use crate::keys;
use crate::paths::{collapse_home, expand_tilde};
use crate::prompt::{KiPrompt, Prompter};

use super::client::ClientHandler;

/// How many times to re-ask for a mistyped password, passphrase or
/// keyboard-interactive answer.
const SECRET_ATTEMPTS: usize = 3;

/// Keys tried by `auto` when no identity files are given, in `~/.ssh`.
const DEFAULT_IDENTITIES: [&str; 3] = ["id_ed25519", "id_ecdsa", "id_rsa"];

/// A private key read from disk. It may still be encrypted: the passphrase
/// is only asked for once the server has accepted the public key.
pub(super) struct KeyFile {
    path: PathBuf,
    key: PrivateKey,
}

impl KeyFile {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let shown = collapse_home(path);
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(match e.kind() {
                ErrorKind::NotFound => format!("key file {shown} not found"),
                _ => format!("cannot read key {shown}: {e}"),
            })
        })?;
        let key = match PrivateKey::from_openssh(&text) {
            Ok(key) => key,
            // Older PEM/PKCS#8 formats.
            Err(_) => match russh::keys::decode_secret_key(&text, None) {
                Ok(key) => key,
                Err(russh::keys::Error::KeyIsEncrypted) => {
                    return Err(Error::Config(format!(
                        "{shown} is an encrypted key in the old PEM format, which is not \
                         supported. Convert it with: ssh-keygen -p -f {shown}"
                    )))
                }
                Err(e) => return Err(Error::Config(format!("cannot load key {shown}: {e}"))),
            },
        };
        Ok(Self {
            path: path.to_path_buf(),
            key,
        })
    }

    /// The key files an auth method will offer, loaded up front so a bad
    /// path is reported before connecting.
    pub(super) fn for_method(auth: &AuthMethod) -> Result<Vec<Self>> {
        match auth {
            AuthMethod::PublicKey { key_path } => Ok(vec![Self::load(&expand_tilde(key_path))?]),
            AuthMethod::Auto { identities } if identities.is_empty() => Ok(default_identities()),
            AuthMethod::Auto { identities } => identities
                .iter()
                .map(|p| Self::load(&expand_tilde(p)))
                .collect(),
            _ => Ok(Vec::new()),
        }
    }

    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    /// Decrypts the key if needed. Returns `false` when the user skips it
    /// (an empty passphrase, as in OpenSSH) or gets it wrong too often.
    async fn unlock(&mut self, prompter: &Arc<dyn Prompter>) -> Result<bool> {
        if !self.key.is_encrypted() {
            return Ok(true);
        }
        let shown = collapse_home(&self.path);
        let label = format!("Passphrase for {shown} (empty to skip): ");
        for _ in 0..SECRET_ATTEMPTS {
            let label = label.clone();
            let passphrase = ask(prompter, move |p| p.secret(&label)).await?;
            if passphrase.is_empty() {
                return Ok(false);
            }
            if let Ok(key) = self.key.decrypt(passphrase) {
                self.key = key;
                return Ok(true);
            }
        }
        tracing::warn!("wrong passphrase for {shown}, skipping the key");
        Ok(false)
    }
}

/// The default `~/.ssh` keys that exist and can be read.
fn default_identities() -> Vec<KeyFile> {
    let Some(ssh_dir) = dirs::home_dir().map(|h| h.join(".ssh")) else {
        return Vec::new();
    };
    DEFAULT_IDENTITIES
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|path| path.exists())
        .filter_map(|path| match KeyFile::load(&path) {
            Ok(key) => Some(key),
            Err(e) => {
                tracing::debug!("skipping {}: {e}", path.display());
                None
            }
        })
        .collect()
}

/// Signs the auth challenge with a key file, unlocking it on first use.
struct FileSigner<'a> {
    key: &'a mut KeyFile,
    prompter: &'a Arc<dyn Prompter>,
    /// Set when the key was not unlocked (an invalid signature was sent).
    skipped: bool,
}

impl russh::Signer for FileSigner<'_> {
    type Error = Error;

    async fn auth_sign(
        &mut self,
        _identity: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let encoding = |e: russh::keys::ssh_encoding::Error| Error::Other(e.to_string());
        if !self.key.unlock(self.prompter).await? {
            // russh waits for a signature once the server has accepted the
            // key, so send one that cannot verify: the server then rejects
            // this key and authentication moves on to the next method.
            self.skipped = true;
            let blob = unverifiable_signature(self.key.public_key().key_data(), hash_alg)
                .and_then(|sig| Ok(sig.encode_vec()?))
                .map_err(|e| Error::Other(e.to_string()))?;
            blob.encode(&mut to_sign).map_err(encoding)?;
            return Ok(to_sign);
        }
        let signature = match self.key.key.key_data() {
            KeypairData::Rsa(keypair) => (keypair, hash_alg).try_sign(&to_sign),
            other => other.try_sign(&to_sign),
        }
        .map_err(|e| Error::Other(format!("signing with {}: {e}", self.key.path.display())))?;
        let blob = signature.encode_vec().map_err(encoding)?;
        blob.encode(&mut to_sign).map_err(encoding)?;
        Ok(to_sign)
    }
}

/// A well-formed signature for `key` that never verifies (all zeros), so
/// the server parses it and rejects the key instead of disconnecting.
fn unverifiable_signature(
    key: &KeyData,
    hash_alg: Option<HashAlg>,
) -> std::result::Result<Signature, ssh_key::Error> {
    let (algorithm, data) = match key {
        KeyData::Rsa(rsa) => {
            let len = rsa.n().as_positive_bytes().map_or(256, <[u8]>::len);
            (Algorithm::Rsa { hash: hash_alg }, vec![0; len])
        }
        KeyData::Ecdsa(ecdsa) => {
            // r = s = 1, as two mpints.
            let one = [0, 0, 0, 1, 1];
            let curve = ecdsa.curve();
            (Algorithm::Ecdsa { curve }, [one, one].concat())
        }
        other => (other.algorithm(), vec![0; 64]),
    };
    Signature::new(algorithm, data)
}

/// Runs a (possibly blocking) prompt without stalling the async executor.
async fn ask<T, F>(prompter: &Arc<dyn Prompter>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&dyn Prompter) -> Option<T> + Send + 'static,
{
    let prompter = prompter.clone();
    tokio::task::spawn_blocking(move || f(prompter.as_ref()))
        .await
        .map_err(|e| Error::Other(format!("prompt task failed: {e}")))?
        .ok_or(Error::Cancelled)
}

/// One authentication attempt, which may chain several methods.
pub(super) struct Authenticator<'a> {
    pub handle: &'a mut Handle<ClientHandler>,
    pub user: &'a str,
    pub host: &'a str,
    pub prompter: &'a Arc<dyn Prompter>,
    /// Methods the server said it still accepts; unknown until the first
    /// failure.
    remaining: Option<MethodSet>,
    /// What was tried, for the error message.
    tried: Vec<String>,
}

impl<'a> Authenticator<'a> {
    pub fn new(
        handle: &'a mut Handle<ClientHandler>,
        user: &'a str,
        host: &'a str,
        prompter: &'a Arc<dyn Prompter>,
    ) -> Self {
        Self {
            handle,
            user,
            host,
            prompter,
            remaining: None,
            tried: Vec::new(),
        }
    }

    /// Returns `Ok(true)` on success; on failure, a description of what was
    /// tried and what the server accepts (for the error message).
    pub async fn run(
        mut self,
        auth: &AuthMethod,
        keys: Vec<KeyFile>,
    ) -> Result<std::result::Result<(), String>> {
        let ok = match auth {
            AuthMethod::Auto { identities } => self.auto(keys, !identities.is_empty()).await?,
            AuthMethod::Password => self.password().await?,
            AuthMethod::PublicKey { .. } => {
                let mut ok = false;
                for key in keys {
                    ok = self.key(key).await?;
                }
                ok
            }
            AuthMethod::Agent => self.agent(&mut Vec::new()).await?,
            AuthMethod::KeyboardInteractive => self.keyboard_interactive().await?,
        };
        Ok(if ok { Ok(()) } else { Err(self.summary()) })
    }

    fn summary(&self) -> String {
        let mut out = String::new();
        if self.tried.is_empty() {
            out.push_str(" (no ssh-agent keys or ~/.ssh/id_* keys to try)");
        } else {
            out.push_str(&format!(" (tried {})", self.tried.join(", ")));
        }
        if let Some(remaining) = &self.remaining {
            let names: Vec<&str> = remaining.iter().map(<&str>::from).collect();
            out.push_str(&format!("; the server accepts: {}", names.join(", ")));
        }
        out
    }

    /// Records the outcome of one attempt; `true` means authenticated.
    fn record(&mut self, result: AuthResult) -> bool {
        match result {
            AuthResult::Success => true,
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                self.remaining = Some(remaining_methods);
                false
            }
        }
    }

    fn allows(&self, method: MethodKind) -> bool {
        self.remaining.as_ref().is_none_or(|r| r.contains(&method))
    }

    /// Explicit key files go first (the user asked for them); otherwise the
    /// agent goes first, as in OpenSSH. A key is never offered twice.
    async fn auto(&mut self, keys: Vec<KeyFile>, explicit: bool) -> Result<bool> {
        let mut offered = Vec::new();
        if !explicit && self.agent(&mut offered).await? {
            return Ok(true);
        }
        for key in keys {
            if !self.allows(MethodKind::PublicKey) {
                break;
            }
            if offered.contains(key.public_key().key_data()) {
                continue;
            }
            offered.push(key.public_key().key_data().clone());
            if self.key(key).await? {
                return Ok(true);
            }
        }
        if explicit && self.allows(MethodKind::PublicKey) && self.agent(&mut offered).await? {
            return Ok(true);
        }

        // Nothing tried yet: ask the server which methods it accepts.
        if self.remaining.is_none() {
            let result = self.handle.authenticate_none(self.user).await?;
            if self.record(result) {
                return Ok(true);
            }
        }

        if self.allows(MethodKind::KeyboardInteractive) {
            let (ok, prompted) = self.keyboard_interactive_rounds().await?;
            // A server may advertise keyboard-interactive without having
            // anything to ask; fall back to a plain password then.
            if ok || prompted {
                return Ok(ok);
            }
        }
        if self.allows(MethodKind::Password) {
            return self.password().await;
        }
        Ok(false)
    }

    async fn password(&mut self) -> Result<bool> {
        self.tried.push("password".into());
        let label = format!("{}@{}'s password: ", self.user, self.host);
        for _ in 0..SECRET_ATTEMPTS {
            let label = label.clone();
            let password = ask(self.prompter, move |p| p.secret(&label)).await?;
            let result = self
                .handle
                .authenticate_password(self.user, password)
                .await?;
            if self.record(result) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn key(&mut self, mut key: KeyFile) -> Result<bool> {
        self.tried.push(collapse_home(&key.path));
        let public = key.public_key().clone();
        let hash_alg = self.rsa_hash(&public).await?;
        let mut signer = FileSigner {
            key: &mut key,
            prompter: self.prompter,
            skipped: false,
        };
        let result = self
            .handle
            .authenticate_publickey_with(self.user, public, hash_alg, &mut signer)
            .await?;
        if signer.skipped {
            if let Some(entry) = self.tried.last_mut() {
                entry.push_str(" (skipped)");
            }
        }
        Ok(self.record(result))
    }

    /// Tries every agent identity not already in `offered`, adding each one
    /// it tries. A missing agent is not an error.
    async fn agent(&mut self, offered: &mut Vec<KeyData>) -> Result<bool> {
        let mut agent = match keys::agent::connect_env().await {
            Ok(agent) => agent,
            Err(e) => {
                tracing::debug!("ssh-agent unavailable: {e}");
                return Ok(false);
            }
        };
        let identities = keys::agent::list_identities(&mut agent).await?;
        if identities.is_empty() {
            return Ok(false);
        }
        self.tried
            .push(format!("ssh-agent ({} keys)", identities.len()));
        for identity in &identities {
            if !self.allows(MethodKind::PublicKey) {
                break;
            }
            let public = identity.public_key().into_owned();
            if offered.contains(public.key_data()) {
                continue;
            }
            offered.push(public.key_data().clone());
            tracing::debug!("trying agent identity: {}", identity.comment());
            let hash_alg = self.rsa_hash(&public).await?;
            let result = self
                .handle
                .authenticate_publickey_with(self.user, public, hash_alg, &mut agent)
                .await?;
            if self.record(result) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// RSA keys need a SHA-2 hash the server supports; other key types
    /// ignore it.
    async fn rsa_hash(&self, key: &PublicKey) -> Result<Option<HashAlg>> {
        if !key.algorithm().is_rsa() {
            return Ok(None);
        }
        Ok(self.handle.best_supported_rsa_hash().await?.flatten())
    }

    async fn keyboard_interactive(&mut self) -> Result<bool> {
        Ok(self.keyboard_interactive_rounds().await?.0)
    }

    /// Runs keyboard-interactive exchanges, retrying after a failure that
    /// followed user input (a mistyped password or code). Returns whether
    /// it succeeded and whether the user was asked anything.
    async fn keyboard_interactive_rounds(&mut self) -> Result<(bool, bool)> {
        self.tried.push("keyboard-interactive".into());
        let mut prompted = false;
        for _ in 0..SECRET_ATTEMPTS {
            let (ok, asked) = self.keyboard_interactive_once().await?;
            prompted |= asked;
            if ok || !asked || !self.allows(MethodKind::KeyboardInteractive) {
                return Ok((ok, prompted));
            }
        }
        Ok((false, prompted))
    }

    /// One exchange: the server may send any number of challenge rounds
    /// (e.g. password, then an OTP code) before deciding.
    async fn keyboard_interactive_once(&mut self) -> Result<(bool, bool)> {
        let mut asked = false;
        let mut response = self
            .handle
            .authenticate_keyboard_interactive_start(self.user, None)
            .await?;
        loop {
            match response {
                KeyboardInteractiveAuthResponse::Success => return Ok((true, asked)),
                KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    let ok = self.record(AuthResult::Failure {
                        remaining_methods,
                        partial_success,
                    });
                    return Ok((ok, asked));
                }
                KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    let answers = if prompts.is_empty() {
                        Vec::new()
                    } else {
                        asked = true;
                        let prompts: Vec<KiPrompt> = prompts
                            .into_iter()
                            .map(|p| KiPrompt {
                                text: p.prompt,
                                echo: p.echo,
                            })
                            .collect();
                        ask(self.prompter, move |p| {
                            p.keyboard_interactive(&name, &instructions, &prompts)
                        })
                        .await?
                    };
                    response = self
                        .handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await?;
                }
            }
        }
    }
}
