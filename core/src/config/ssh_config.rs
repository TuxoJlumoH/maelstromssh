//! A subset of OpenSSH's `ssh_config`: `Host`, `Match`, `Include`,
//! `HostName`, `User`, `Port` and `IdentityFile`. Other keywords are ignored.
//!
//! As in OpenSSH, the user file (`~/.ssh/config`) is read before the system
//! one (`/etc/ssh/ssh_config`), and the first value found for a keyword wins
//! (except `IdentityFile`, which accumulates).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::paths::expand_tilde;

/// Nested `Include`s deeper than this are reported as an error (loops).
const MAX_INCLUDE_DEPTH: usize = 16;

/// The settings that apply to one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConfig {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Paths with `~` and `%` tokens already expanded, in config order.
    pub identity_files: Vec<String>,
    /// Keywords that change how to connect but are not supported (e.g.
    /// `ProxyJump`), so the user can be warned.
    pub unsupported: Vec<String>,
}

/// Keywords whose absence would make the connection go somewhere else or
/// fail in a confusing way.
const UNSUPPORTED: [&str; 3] = ["proxyjump", "proxycommand", "certificatefile"];

#[derive(Debug, Clone)]
enum Condition {
    /// `Host` patterns.
    Host(Vec<String>),
    /// `Match` criteria, all of which must hold.
    Match(Vec<Criterion>),
}

#[derive(Debug, Clone)]
enum Criterion {
    All,
    Host(Vec<String>),
    OriginalHost(Vec<String>),
    User(Vec<String>),
    LocalUser(Vec<String>),
    /// `final` and `canonical` are fixed outcomes here; criteria we cannot
    /// evaluate (`exec`, `localnetwork`, …) never match.
    Fixed(bool),
}

#[derive(Debug, Clone)]
enum Item {
    Block(Condition),
    Include(Vec<Item>),
    Setting {
        key: String,
        value: String,
        location: String,
    },
}

/// Parsed configuration files, ready for [`SshConfig::lookup`].
#[derive(Debug, Clone, Default)]
pub struct SshConfig {
    items: Vec<Item>,
}

impl SshConfig {
    /// Reads `~/.ssh/config` and `/etc/ssh/ssh_config`; missing files are
    /// fine, broken ones are an error.
    pub fn load_default() -> Result<Self> {
        let mut config = Self::default();
        if let Some(home) = dirs::home_dir() {
            let ssh_dir = home.join(".ssh");
            config.append_file(&ssh_dir.join("config"), &ssh_dir)?;
        }
        let etc = Path::new("/etc/ssh");
        config.append_file(&etc.join("ssh_config"), etc)?;
        Ok(config)
    }

    /// Parses one file. Relative `Include` paths resolve against `base`.
    pub fn from_file(path: &Path, base: &Path) -> Result<Self> {
        let mut config = Self::default();
        config.append_file(path, base)?;
        Ok(config)
    }

    pub fn parse(text: &str, base: &Path) -> Result<Self> {
        Ok(Self {
            items: parse(text, "config", base, 0)?,
        })
    }

    fn append_file(&mut self, path: &Path, base: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        // Each file starts outside any Host block, as in OpenSSH.
        self.items
            .push(Item::Block(Condition::Match(vec![Criterion::All])));
        self.items.extend(parse_file(path, base, 0)?);
        Ok(())
    }

    /// Host aliases written without wildcards, for pickers and completion.
    pub fn host_aliases(&self) -> Vec<String> {
        let mut out = Vec::new();
        collect_aliases(&self.items, &mut out);
        out
    }

    /// The settings for `host` as typed by the user. `user` is the user
    /// given on the command line, if any (it is used by `Match user` and
    /// `%r`).
    pub fn lookup(&self, host: &str, user: Option<&str>) -> Result<HostConfig> {
        let mut state = Lookup {
            original: host,
            cli_user: user,
            local_user: local_user(),
            out: HostConfig::default(),
            identity_raw: Vec::new(),
        };
        let mut active = true;
        state.walk(&self.items, &mut active)?;

        let hostname = state.out.hostname.clone().unwrap_or_else(|| host.into());
        let remote_user = user
            .map(str::to_string)
            .or_else(|| state.out.user.clone())
            .unwrap_or_else(|| state.local_user.clone());
        let port = state.out.port.unwrap_or(22);
        state.out.identity_files = state
            .identity_raw
            .iter()
            .map(|raw| {
                let tokens = Tokens {
                    host: &hostname,
                    original: host,
                    user: &remote_user,
                    local_user: &state.local_user,
                    port,
                };
                let expanded = expand_tokens(raw, &tokens)?;
                Ok(expand_tilde(expanded).display().to_string())
            })
            .collect::<Result<_>>()?;
        Ok(state.out)
    }
}

fn collect_aliases(items: &[Item], out: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Block(Condition::Host(patterns)) => {
                for p in patterns {
                    if !p.starts_with('!') && !p.contains(['*', '?']) && !out.contains(p) {
                        out.push(p.clone());
                    }
                }
            }
            Item::Include(inner) => collect_aliases(inner, out),
            _ => {}
        }
    }
}

struct Lookup<'a> {
    original: &'a str,
    cli_user: Option<&'a str>,
    local_user: String,
    out: HostConfig,
    identity_raw: Vec<String>,
}

impl Lookup<'_> {
    fn walk(&mut self, items: &[Item], active: &mut bool) -> Result<()> {
        for item in items {
            match item {
                Item::Block(condition) => *active = self.matches(condition),
                Item::Include(inner) if *active => {
                    // An included file starts matching everything, and its
                    // last block does not leak into the including file.
                    let mut inner_active = true;
                    self.walk(inner, &mut inner_active)?;
                }
                Item::Include(_) => {}
                Item::Setting {
                    key,
                    value,
                    location,
                } if *active => self.apply(key, value, location)?,
                Item::Setting { .. } => {}
            }
        }
        Ok(())
    }

    fn matches(&self, condition: &Condition) -> bool {
        match condition {
            Condition::Host(patterns) => match_list(patterns, self.original),
            Condition::Match(criteria) => criteria.iter().all(|c| match c {
                Criterion::All => true,
                Criterion::Host(p) => {
                    let host = self.out.hostname.as_deref().unwrap_or(self.original);
                    match_list(p, host)
                }
                Criterion::OriginalHost(p) => match_list(p, self.original),
                Criterion::User(p) => {
                    let user = self
                        .cli_user
                        .or(self.out.user.as_deref())
                        .unwrap_or(&self.local_user);
                    match_list(p, user)
                }
                Criterion::LocalUser(p) => match_list(p, &self.local_user),
                Criterion::Fixed(b) => *b,
            }),
        }
    }

    fn apply(&mut self, key: &str, value: &str, location: &str) -> Result<()> {
        match key {
            "hostname" if self.out.hostname.is_none() => {
                self.out.hostname = Some(value.replace("%h", self.original).replace("%%", "%"));
            }
            "user" if self.out.user.is_none() => self.out.user = Some(value.to_string()),
            "port" if self.out.port.is_none() => {
                let port = value
                    .parse()
                    .map_err(|_| Error::Config(format!("{location}: invalid port '{value}'")))?;
                self.out.port = Some(port);
            }
            "identityfile" if !value.eq_ignore_ascii_case("none") => {
                if !self.identity_raw.iter().any(|v| v == value) {
                    self.identity_raw.push(value.to_string());
                }
            }
            k if UNSUPPORTED.contains(&k) && !value.eq_ignore_ascii_case("none") => {
                let note = format!("{location}: {k}");
                if !self.out.unsupported.contains(&note) {
                    self.out.unsupported.push(note);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

struct Tokens<'a> {
    host: &'a str,
    original: &'a str,
    user: &'a str,
    local_user: &'a str,
    port: u16,
}

fn expand_tokens(raw: &str, t: &Tokens) -> Result<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(t.host),
            Some('n') => out.push_str(t.original),
            Some('r') => out.push_str(t.user),
            Some('u') => out.push_str(t.local_user),
            Some('p') => out.push_str(&t.port.to_string()),
            Some('d') => {
                let home = dirs::home_dir()
                    .ok_or_else(|| Error::Config("no home directory for %d".into()))?;
                out.push_str(&home.display().to_string());
            }
            other => {
                return Err(Error::Config(format!(
                    "unsupported token %{} in '{raw}'",
                    other.map(String::from).unwrap_or_default()
                )))
            }
        }
    }
    Ok(out)
}

fn local_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

/// OpenSSH pattern lists: any negated match rejects, otherwise any
/// positive match accepts.
fn match_list(patterns: &[String], value: &str) -> bool {
    let mut matched = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if wildcard(neg, value) {
                return false;
            }
        } else if wildcard(p, value) {
            matched = true;
        }
    }
    matched
}

/// `*` and `?` wildcards, case-insensitive like OpenSSH host matching.
fn wildcard(pattern: &str, value: &str) -> bool {
    fn inner(p: &[char], v: &[char]) -> bool {
        match p.split_first() {
            None => v.is_empty(),
            Some(('*', rest)) => (0..=v.len()).any(|i| inner(rest, &v[i..])),
            Some(('?', rest)) => !v.is_empty() && inner(rest, &v[1..]),
            Some((c, rest)) => v
                .split_first()
                .is_some_and(|(d, v)| c.eq_ignore_ascii_case(d) && inner(rest, v)),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    inner(&p, &v)
}

fn parse_file(path: &Path, base: &Path, depth: usize) -> Result<Vec<Item>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
    parse(&text, &path.display().to_string(), base, depth)
}

fn parse(text: &str, name: &str, base: &Path, depth: usize) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let location = format!("{name}:{}", n + 1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let split = line
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(line.len());
        let key = line[..split].to_ascii_lowercase();
        let rest = line[split..].trim_start();
        let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
        let args = split_args(rest).map_err(|e| Error::Config(format!("{location}: {e}")))?;
        let bad = |msg: &str| Error::Config(format!("{location}: {msg}"));

        match key.as_str() {
            "host" => {
                if args.is_empty() {
                    return Err(bad("Host needs at least one pattern"));
                }
                items.push(Item::Block(Condition::Host(args)));
            }
            "match" => items.push(Item::Block(Condition::Match(
                parse_match(&args).map_err(|e| bad(&e))?,
            ))),
            "include" => {
                if depth >= MAX_INCLUDE_DEPTH {
                    return Err(bad("too many nested Include directives"));
                }
                let mut inner = Vec::new();
                for arg in &args {
                    let path = expand_tilde(arg);
                    let path = if path.is_absolute() {
                        path
                    } else {
                        base.join(path)
                    };
                    for file in glob(&path) {
                        inner.extend(parse_file(&file, base, depth + 1)?);
                    }
                }
                items.push(Item::Include(inner));
            }
            _ => {
                let Some(value) = args.into_iter().next() else {
                    return Err(bad(&format!("missing value for '{key}'")));
                };
                items.push(Item::Setting {
                    key,
                    value,
                    location,
                });
            }
        }
    }
    Ok(items)
}

fn parse_match(args: &[String]) -> std::result::Result<Vec<Criterion>, String> {
    let mut criteria = Vec::new();
    let mut it = args.iter();
    while let Some(word) = it.next() {
        let (negate, word) = match word.strip_prefix('!') {
            Some(w) => (true, w),
            None => (false, word.as_str()),
        };
        let word = word.to_ascii_lowercase();
        let criterion = match word.as_str() {
            "all" => Criterion::All,
            "canonical" => Criterion::Fixed(false),
            "final" => Criterion::Fixed(true),
            _ => {
                let arg = it
                    .next()
                    .ok_or_else(|| format!("Match {word} needs an argument"))?;
                let list = || arg.split(',').map(str::to_string).collect();
                match word.as_str() {
                    "host" => Criterion::Host(list()),
                    "originalhost" => Criterion::OriginalHost(list()),
                    "user" => Criterion::User(list()),
                    "localuser" => Criterion::LocalUser(list()),
                    _ => {
                        tracing::debug!("ssh_config: unsupported Match {word}, treated as false");
                        Criterion::Fixed(false)
                    }
                }
            }
        };
        criteria.push(if negate {
            negated(criterion)
        } else {
            criterion
        });
    }
    if criteria.is_empty() {
        return Err("Match needs at least one criterion".into());
    }
    Ok(criteria)
}

/// `!criterion`: wraps the pattern list in a negation.
fn negated(c: Criterion) -> Criterion {
    let neg = |p: Vec<String>| {
        let mut out = vec!["*".to_string()];
        out.extend(p.into_iter().map(|p| format!("!{p}")));
        out
    };
    match c {
        Criterion::All => Criterion::Fixed(false),
        Criterion::Fixed(b) => Criterion::Fixed(!b),
        Criterion::Host(p) => Criterion::Host(neg(p)),
        Criterion::OriginalHost(p) => Criterion::OriginalHost(neg(p)),
        Criterion::User(p) => Criterion::User(neg(p)),
        Criterion::LocalUser(p) => Criterion::LocalUser(neg(p)),
    }
}

/// Splits on whitespace, keeping double-quoted strings together.
fn split_args(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    args.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quoted {
        return Err("unterminated quote".into());
    }
    if in_word {
        args.push(cur);
    }
    Ok(args)
}

/// Expands `*`/`?` in any path component; results are sorted.
fn glob(path: &Path) -> Vec<PathBuf> {
    let mut found = vec![PathBuf::from("/")];
    for comp in path.components().skip(1) {
        let comp = comp.as_os_str().to_string_lossy();
        let mut next = Vec::new();
        for dir in &found {
            if !comp.contains(['*', '?']) {
                next.push(dir.join(comp.as_ref()));
                continue;
            }
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with('.') && wildcard(&comp, &name) {
                    next.push(entry.path());
                }
            }
        }
        found = next;
    }
    found.retain(|p| p.is_file());
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(text: &str) -> SshConfig {
        SshConfig::parse(text, Path::new("/nonexistent")).unwrap()
    }

    #[test]
    fn first_value_wins_and_identities_accumulate() {
        let c = cfg("
            Host web
                HostName 10.0.0.5
                User deploy
                IdentityFile /keys/web
            Host *
                User nobody
                Port 2200
                IdentityFile /keys/default
        ");
        let h = c.lookup("web", None).unwrap();
        assert_eq!(h.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(h.user.as_deref(), Some("deploy"));
        assert_eq!(h.port, Some(2200));
        assert_eq!(h.identity_files, ["/keys/web", "/keys/default"]);

        let other = c.lookup("elsewhere", None).unwrap();
        assert_eq!(other.hostname, None);
        assert_eq!(other.user.as_deref(), Some("nobody"));
    }

    #[test]
    fn patterns_negation_and_equals_syntax() {
        let c = cfg("
            Host *.example.com !secret.example.com
              Port=2222
            Host \"db?\"
              hostname = %h.internal
        ");
        assert_eq!(c.lookup("a.example.com", None).unwrap().port, Some(2222));
        assert_eq!(c.lookup("A.EXAMPLE.COM", None).unwrap().port, Some(2222));
        assert_eq!(c.lookup("secret.example.com", None).unwrap().port, None);
        assert_eq!(
            c.lookup("db1", None).unwrap().hostname.as_deref(),
            Some("db1.internal")
        );
        assert_eq!(c.lookup("db10", None).unwrap().hostname, None);
    }

    #[test]
    fn match_criteria() {
        let c = cfg("
            Host jump
              HostName jump.corp.net
            Match host *.corp.net user admin
              Port 2022
            Match originalhost jump !user root
              IdentityFile /keys/%r@%h:%p
            Match exec \"true\"
              User never
        ");
        let h = c.lookup("jump", Some("admin")).unwrap();
        assert_eq!(h.port, Some(2022));
        assert_eq!(h.user, None);
        assert_eq!(h.identity_files, ["/keys/admin@jump.corp.net:2022"]);
        let h = c.lookup("jump", Some("root")).unwrap();
        assert_eq!(h.port, None);
        assert!(h.identity_files.is_empty());
    }

    #[test]
    fn reports_unsupported_keywords() {
        let c = cfg("Host a\n  ProxyJump bastion\nHost b\n  ProxyJump none");
        assert_eq!(
            c.lookup("a", None).unwrap().unsupported,
            ["config:2: proxyjump"]
        );
        assert!(c.lookup("b", None).unwrap().unsupported.is_empty());
    }

    #[test]
    fn aliases_skip_wildcards() {
        let c = cfg("Host a b *.x !c\nHost b d?");
        assert_eq!(c.host_aliases(), ["a", "b"]);
    }

    #[test]
    fn errors_name_the_line() {
        let err = SshConfig::parse("Host x\n  Port abc", Path::new("/"))
            .unwrap()
            .lookup("x", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("config:2") && err.contains("abc"), "{err}");
        assert!(SshConfig::parse("Host", Path::new("/")).is_err());
    }

    #[test]
    fn includes_are_globbed_and_conditional() {
        let dir = std::env::temp_dir().join(format!("vortexssh-sshcfg-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("conf.d")).unwrap();
        std::fs::write(dir.join("conf.d/b.conf"), "Host inc\n  Port 2\n").unwrap();
        std::fs::write(dir.join("conf.d/a.conf"), "Host inc\n  Port 1\n").unwrap();
        std::fs::write(dir.join("other"), "User fromother\n").unwrap();
        std::fs::write(
            dir.join("config"),
            "Include conf.d/*.conf\nHost only\n  Include other\nHost inc\n  User late\n",
        )
        .unwrap();
        let c = SshConfig::from_file(&dir.join("config"), &dir).unwrap();
        let h = c.lookup("inc", None).unwrap();
        assert_eq!((h.port, h.user.as_deref()), (Some(1), Some("late")));
        assert_eq!(
            c.lookup("only", None).unwrap().user.as_deref(),
            Some("fromother")
        );
        assert_eq!(c.host_aliases(), ["inc", "only"]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
