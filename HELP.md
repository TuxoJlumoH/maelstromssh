# VortexSSH — Help & Reference

A Rust SSH/SFTP client with three front-ends (`vortexssh` CLI, `vortexssh-tui`
terminal UI, `vortexssh-gui` graphical UI) all driven by one UI-agnostic engine
(`vortexssh-core`).

- Workspace: `~/Projects/vortexssh`
- Crates: `core/` (library), `cli/`, `tui/`, `gui/` (binaries)
- Config dir: `~/.config/vortexssh/profiles/*.toml`

---

## 1. Build

```bash
cd ~/Projects/vortexssh
cargo build --release            # builds all three binaries
cargo test --workspace           # run the test suite
```

Binaries end up in `target/release/` (or `target/debug/` after `cargo build`).

Install and packaging (see the `Makefile`):

| Command | Result |
|---|---|
| `make` | `cargo build --release --locked` |
| `sudo make install` | binaries, `.desktop` entry, icons, docs and licenses under `/usr/local` (`PREFIX=`, `DESTDIR=` supported) |
| `make uninstall` | removes what `install` copied (same `PREFIX`) |
| `make dist` | `dist/vortexssh-<ver>-<arch>-linux.tar.gz` + `.sha256` |
| `make deb` | `dist/vortexssh_<ver>-1_<arch>.deb` (needs `cargo install cargo-deb`) |

`packaging/aur/PKGBUILD` builds an Arch package from a release tag.

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, clippy with
`-D warnings` and the tests on every push to `main` and every pull request.
Pushing a `v*` tag that matches the `Cargo.toml` version
(`.github/workflows/release.yml`) publishes a GitHub release with the
tarball and the `.deb`.

Releasing:

1. Bump `version` in the root `Cargo.toml`, run `cargo build` to update
   `Cargo.lock`, and commit.
2. `git tag vX.Y.Z && git push origin main vX.Y.Z`.
3. Update `pkgver` in `packaging/aur/PKGBUILD`, then run `updpkgsums` and
   `makepkg --printsrcinfo > .SRCINFO` (and push to the AUR repo if published there).

---

## 2. Authentication methods

Every front-end shares the same `--auth` selection. The value applies per
connection; a profile stores it for reuse.

| `--auth` value | Meaning |
|---|---|
| `auto` | Like OpenSSH: `ssh-agent` keys, then key files, then keyboard-interactive or a password prompt (whatever the server accepts). |
| `password` | Prompt for a password (never stored in a profile). Up to 3 attempts. |
| `key` | Public-key auth; needs `-i/--identity <PATH>` (OpenSSH format). Prompts for a passphrase if the key is encrypted. |
| `agent` | Delegate to a running `ssh-agent` (via `$SSH_AUTH_SOCK`); every identity is tried. |
| `keyboard-interactive` | Server-driven prompts, e.g. password followed by a 2FA/OTP code. |

The **default** is `auto`. Without `-i` it tries the agent, then the default
keys `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa` and `~/.ssh/id_rsa`. With `-i` that
key is tried first, then the agent. The same key is never offered twice, and
a key's passphrase is only asked for once the server accepts the key. An empty
passphrase (or three wrong ones) skips that key and moves on, like OpenSSH. Use
`--auth key` to try *only* the given key. When everything fails, the error
lists what was tried and which methods the server accepts.

Host keys are verified against `~/.ssh/known_hosts` (trust-on-first-use with a
confirmation prompt; a *changed* key is always rejected). Host certificates
are not supported yet and are rejected with an explanation.

---

### `~/.ssh/config`

When connecting to a `TARGET` (not `--profile`), `~/.ssh/config` and then
`/etc/ssh/ssh_config` are read, as OpenSSH does, so host aliases work:

```
Host web
    HostName 10.0.0.5
    User deploy
    Port 2222
    IdentityFile ~/.ssh/web_key
```

`vortexssh connect web` then connects to `deploy@10.0.0.5:2222` with that key.

- Supported: `Host` (with `*`, `?` and `!` patterns), `Match` (`all`, `host`,
  `originalhost`, `user`, `localuser`, `final`; others never match),
  `Include` (with globs), `HostName`, `User`, `Port`, `IdentityFile` (with
  `~` and the `%h %n %r %u %p %d %%` tokens).
- The first value found wins; `IdentityFile`s add up. `IdentityFile`s that
  don't exist are skipped.
- Command-line `user@`, `-p`, `-i` and `--auth` take priority.
- `ProxyJump`, `ProxyCommand` and `CertificateFile` are not supported. You get
  a warning when they apply. Other keywords are ignored silently.
- A malformed file is an error that names the file and line.

---

## 3. CLI — `vortexssh`

```
vortexssh <SUBCOMMAND>
```

### `connect` — open an interactive shell

```
vortexssh connect [TARGET] [OPTIONS]
```

| Argument / flag | Description |
|---|---|
| `TARGET` | `user@host`, or just `host` (defaults to `$USER`). Omit when using `--profile`. |
| `-p, --port <PORT>` | Port (default `22`). |
| `-i, --identity <PATH>` | Private key to try first (`~` is expanded). |
| `--profile <NAME>` | Load settings from a saved profile (conflicts with `TARGET`). |
| `--auth <AUTH>` | Auth method (default `auto`, see §2). |
| `-L, --local-forward <SPEC>` | Local forward `[bind:]port:host:hostport` (repeatable). |
| `-R, --remote-forward <SPEC>` | Remote forward `[bind:]port:host:hostport` (repeatable). |
| `-D, --dynamic-forward <SPEC>` | SOCKS5 forward `[bind:]port` (repeatable). |

```bash
vortexssh connect user@example.com
vortexssh connect -i ~/.ssh/id_ed25519 git@github.com
vortexssh connect --profile prod-web

# Port forwarding
vortexssh connect -L 8080:localhost:80 user@example.com        # local
vortexssh connect -R 9000:db.internal:5432 user@example.com    # remote
vortexssh connect -D 1080 user@example.com                     # SOCKS5 proxy
vortexssh connect -L 127.0.0.1:8080:localhost:80 user@host     # bind a specific local addr
```

### `profile` — manage saved profiles

```
vortexssh profile add <NAME> <TARGET> [OPTIONS]
vortexssh profile list
vortexssh profile show <NAME>
vortexssh profile rm <NAME>
```

`add` options: `-u, --user <USER>`, `-p, --port <PORT>`, `--auth <AUTH>`,
`-i, --identity <PATH>`, `-L`/`-R`/`-D` (forward specs, repeatable).

```bash
vortexssh profile add mybox user@10.0.0.5 -p 2222 -i ~/.ssh/id_ed25519
vortexssh profile list
vortexssh profile show mybox
vortexssh profile rm mybox
```

### `keygen` — generate an SSH keypair

```
vortexssh keygen [OPTIONS]
```

| Flag | Description |
|---|---|
| `-o, --output <PATH>` | Private key path; the public key is written to `<path>.pub` (default `id_ed25519` / `id_rsa` by type). |
| `-c, --comment <COMMENT>` | Key comment (default empty). |
| `-t, --type <ed25519\|rsa>` | Key type (default `ed25519`). |
| `-b, --bits <BITS>` | RSA modulus size in bits (default `3072`; ignored for ed25519). |

```bash
vortexssh keygen                               # ed25519 -> id_ed25519
vortexssh keygen -t rsa                        # rsa (3072) -> id_rsa
vortexssh keygen -t rsa -b 4096 -o ~/.ssh/id_rsa -c "me@host"
```

### `sftp` — transfer files

One-shot (scriptable) or interactive. Shares the `--port`/`--identity`/
`--profile`/`--auth` options with `connect`.

```bash
vortexssh sftp user@host                      # interactive shell
vortexssh sftp user@host get app.log          # download to ./app.log
vortexssh sftp user@host get app.log /tmp/a   # download to a specific path
vortexssh sftp user@host put ./app.log app.log
vortexssh sftp user@host ls /var/log
vortexssh sftp user@host rm app.log
vortexssh sftp user@host mkdir backups
vortexssh sftp user@host rename old.txt new.txt
```

One-shot subcommands: `get <remote> [local]`, `put <local> [remote]`,
`ls [path]`, `rm <path>`, `mkdir <path>`, `rename <from> <to>`.

Interactive shell commands:

| Command | Description |
|---|---|
| `get <remote> [local]` | download a file |
| `put <local> [remote]` | upload a file |
| `ls [path]` / `cd <path>` / `pwd` | remote listing/navigation |
| `rm` / `mkdir` / `rmdir` / `rename` | remote mutations |
| `lls [path]` / `lcd <path>` / `lpwd` | local listing/navigation |
| `help` / `exit` | help / quit |

Transfers stream in 64 KiB chunks (no whole-file buffering); single files
only (recursive directory transfer is not implemented yet).

---

## 4. TUI — `vortexssh-tui`

Full-screen terminal UI (`ratatui`). Same flags as the GUI; auth/password
prompts happen on the ordinary terminal before the TUI takes over.

```
vortexssh-tui [TARGET] [OPTIONS]
```

| Argument / flag | Description |
|---|---|
| `TARGET` | `user@host` or `host`. |
| `-p, --port <PORT>` | Port (default `22`). |
| `-i, --identity <PATH>` | Private key to try first (`~` is expanded). |
| `--profile <NAME>` | Load a saved profile (conflicts with `TARGET`). |
| `--auth <AUTH>` | Auth method (default `auto`, see §2). |

```bash
vortexssh-tui user@example.com
vortexssh-tui --profile mybox
```

Controls: type normally; `Ctrl+]` quits; mouse wheel / `Shift+PgUp`/`PgDn`
scrolls back; window resize resizes the remote PTY.

---

## 5. GUI — `vortexssh-gui`

Graphical window (`egui`/`eframe`). Same flags as the TUI. Authentication
(password/passphrase/2FA prompts and host-key confirmation) happens **inside the
window**, so it can be launched from a desktop menu without a terminal.

```
vortexssh-gui [TARGET] [OPTIONS]
```

```bash
vortexssh-gui                      # opens the connect form
vortexssh-gui user@example.com
vortexssh-gui -i ~/.ssh/id_ed25519 git@github.com
vortexssh-gui --profile mybox
```

Without a `TARGET` or `--profile`, the window opens on a **connect form**. It has
host (`user@host` or an ssh_config alias), port, an optional key file, the auth
method, a saved-profile picker, and buttons for the `Host` aliases in
`~/.ssh/config`. If the arguments don't resolve (e.g. an unknown profile),
the form opens with the error shown. When a connection fails, **Change…**
returns to the form, prefilled.

In-window controls:

| Action | How |
|---|---|
| Type / run commands | normal typing |
| Interrupt / EOF / paste | `Ctrl+C` · `Ctrl+D` · `Ctrl+V` |
| Scroll back | mouse wheel, or `Shift`+`↑/↓`/`PgUp`/`PgDn` |
| Quit | `Ctrl+Shift+Q` (or close the window) |
| Resize remote terminal | resize the window |

Arrows / Home / End / F-keys / `Alt`+key are forwarded; mouse reporting
(vim/tmux) and bracketed paste are supported.

---

## 6. Profiles (file format)

Profiles are TOML files at `~/.config/vortexssh/profiles/<name>.toml`.

```toml
name = "mybox"
host = "10.0.0.5"
port = 2222
user = "admin"
auth = { method = "public_key", key_path = "/home/me/.ssh/id_ed25519" }

# optional:
forwards = [
  { kind = "local", bind_host = "127.0.0.1", bind_port = 8080, dest_host = "localhost", dest_port = 80 },
]
terminal = { term_type = "xterm-256color", scrollback_lines = 10000 }
```

`auth` methods serialize as `auto` (with optional `identities`), `password`,
`public_key` (with `key_path`), `agent`, or `keyboard_interactive`. `auth`,
`forwards` and `terminal` are optional; a missing `auth` means `auto`.

---

## 7. Core library (`vortexssh-core`) — functions

The engine every front-end uses. No UI/rendering code lives here.

### `config` — persisted profiles

- `Profile { name, host, port, user, auth, forwards, terminal }`
- `AuthMethod::{ Auto{identities}, Password, PublicKey{key_path}, Agent, KeyboardInteractive }` (default `Auto` with no identities)
- `ForwardRule { kind, bind_host, bind_port, dest_host, dest_port }` / `ForwardKind::{ Local, Remote, Dynamic }`
- `TerminalSettings { term_type, scrollback_lines, color_scheme }`
- `ProfileStore` — `new(dir)`, `default_location()`, `list()`, `load(name)`, `save(&profile)`, `delete(name)`

### `keys` — key generation & import/export

- `generate(KeyKind, comment) -> PrivateKey`
- `load_openssh(path, passphrase) -> PrivateKey`
- `save_openssh(&PrivateKey, path)`
- `KeyKind::{ Ed25519, Rsa{bits} }` (RSA min 2048 bits)
- `HashAlg::{ Sha256, ... }` (re-exported)
- `keys::agent` — `connect_env()`, `list_identities(agent)` for `ssh-agent` (`$SSH_AUTH_SOCK`)

### `target` / `prompt` — shared front-end plumbing

- `TargetArgs { target, port, identity, profile, auth }` (`clap::Args` with the
  `clap` feature) → `resolve() -> Target { host, port, user, auth, forwards, warnings }`
  (`resolve_with(&ProfileStore, &SshConfig)` for explicit sources)
- `SshConfig` — `load_default()`, `from_file(path, base)`, `parse(text, base)`,
  `lookup(host, user) -> HostConfig { hostname, user, port, identity_files, unsupported }`,
  `host_aliases()`
- `Prompter` trait — `secret`, `confirm_host_key`, `keyboard_interactive`;
  `TtyPrompter` (terminal, `tty` feature) and `NoPrompt`

### `ssh` — transport & sessions

- `Session::connect(host, port, user, &AuthMethod, prompter, verifier) -> Session`
- `Session::open_shell(term_type, cols, rows) -> Channel` (PTY + shell)
- `Session::open_exec(command) -> Channel` (one-shot, no PTY)
- `Session::open_subsystem(name) -> Channel` (e.g. `"sftp"`)
- `Session::disconnect()`
- `HostKeyVerifier` trait — `verify(&self, host, port, key) -> Result<bool>`
- `KnownHosts { prompter }` (TOFU + known_hosts), `AcceptAll` (tests only)
- `ServerEvent::{ ForwardedTcpIp{..} }`
- Re-exports: `Channel`, `ChannelMsg`, `Msg` (so front-ends never touch `russh`)

### `sftp` — file transfer

- `open(&mut Session) -> SftpSession` — opens the subsystem channel.
- `get(sftp, remote, local) -> Result<u64>` — streaming download (64 KiB chunks).
- `put(sftp, local, remote) -> Result<u64>` — streaming upload.
- `list(sftp, path) -> Result<Vec<DirEntry>>` — sorted directory listing
  (`DirEntry { name, is_dir, size }`).
- `canonicalize`, `remove_file`, `remove_dir`, `create_dir`, `rename`
- Re-exports `SftpSession` so front-ends can name the type.

### `term` — terminal emulation (the renderer-agnostic core)

- `Terminal::new(cols, rows)` / `Terminal::with_scrollback(cols, rows, max)`
- `resize(cols, rows)` — reflows on width change, VTE-style height adjust
- `feed(&[u8])` — push host output through the VT parser
- `take_responses() -> Vec<u8>` — DA/DSR/CPR responses owed to the host
- `cols()`, `rows()`, `cursor_position()`, `cursor_visible()`
- `viewport_line(i) -> &Line`, `viewport_offset()`, `scrollback_len()`
- `scroll_up(n)`, `scroll_down(n)`, `scroll_to_bottom()`
- `title() -> Option<&str>` (OSC 0/2)
- Mode getters for front-ends: `application_cursor_keys()`, `application_keypad()`,
  `mouse_reporting()`, `mouse_sgr()`, `bracketed_paste()`
- `generation()` — bumped on change, for skipping redundant redraws
- Supporting types: `Cell { ch, attrs, wide, continuation }`,
  `Attrs { fg, bg, bold, faint, italic, underline, blink, reverse, hidden, strikethrough }`,
  `Color::{ Default, Indexed(u8), Rgb(u8,u8,u8) }`, `Line`, `Grid`, `MouseMode`, `DEFAULT_SCROLLBACK`

Supported sequences include: SGR (256-color + truecolor), cursor movement,
ED/EL/ECH/ICH/DCH, IL/DL, SU/SD, DECSTBM scroll regions, DECOM origin mode,
alternate screen (`?1049`), RIS, DECSTR, REP, DECCKM/DECPAM, mouse modes
(1000/1002/1003/1006), bracketed paste (2004), and OSC titles.

### `tunnel` — port forwarding

- `start_all(&mut Session, &[ForwardRule]) -> Result<Vec<ForwardInfo>>` — starts
  local, remote, and dynamic (SOCKS5) forwards; returns a printable summary per
  forward.
- `forward_local(handle, bind_host, bind_port, dest_host, dest_port)` — bind a
  local listener, relay each connection over `direct-tcpip`.
- `forward_dynamic(handle, bind_host, bind_port)` — local SOCKS5 proxy.
- `ForwardInfo::{ Local, Remote, Dynamic }` (implements `Display`).
- `parse_socks_addr(&[u8])` — pure SOCKS5 address parser (unit-tested).

The `ssh` module adds `ClientHandle` (a shareable `Arc` of the channel-opening
handle) and `Session::handle()` / `Session::take_events()` for background
forwarding tasks.

### `error`

- `Result<T>` = `std::result::Result<T, Error>`
- `Error::{ Ssh, Sftp, Key, RusshKey, AgentAuth, Io, Config, Connect, HostKeyVerification, HostKeyRejected, AuthFailed, Cancelled, Other }`

---

## 8. Data flow (how the front-ends use the core)

1. Resolve connection settings (CLI args or a `Profile`).
2. `Session::connect(...)`, which asks the front-end's `Prompter` for secrets,
   2FA answers and host-key confirmation only when the server needs them.
3. `open_shell(term_type, cols, rows)`.
4. Loop: read `ChannelMsg::Data` → `Terminal::feed(&data)` → drain
   `take_responses()` → write back via `channel.data(...)`; send local input
   via `channel.data(...)`; forward resizes via `channel.window_change(...)`.
5. Render by walking `Terminal::viewport_line(i)` and mapping `Cell`/`Attrs` to
   each front-end's styling model (ratatui `Style`, egui `Color32`, …).

The TUI/GUI run the SSH I/O on a background tokio task and keep the `Terminal`
on the UI thread; the CLI drives it directly in an async loop.
