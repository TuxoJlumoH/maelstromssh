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

---

## 2. Authentication methods

Every front-end shares the same `--auth` selection. The value applies per
connection; a profile stores it for reuse.

| `--auth` value | Meaning |
|---|---|
| `password` | Prompt for a password (never stored in a profile). |
| `key` | Public-key auth; needs `-i/--identity <PATH>` (OpenSSH format). Prompts for a passphrase if the key is encrypted. |
| `agent` | Delegate to a running `ssh-agent` (via `$SSH_AUTH_SOCK`); every identity is tried. |
| `keyboard-interactive` | Currently degrades to a password prompt; full 2FA prompts are planned. |

The **default** is `password`, or `key` when `-i/--identity` is given without an
explicit `--auth`.

Host keys are verified against `~/.ssh/known_hosts` (trust-on-first-use with a
confirmation prompt; a *changed* key is always rejected).

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
| `-i, --identity <PATH>` | Private key path. |
| `--profile <NAME>` | Load settings from a saved profile (conflicts with `TARGET`). |
| `--auth <AUTH>` | Override the auth method. |
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
| `-i, --identity <PATH>` | Private key path. |
| `--profile <NAME>` | Load a saved profile (conflicts with `TARGET`). |
| `--auth <AUTH>` | Override the auth method. |

```bash
vortexssh-tui user@example.com
vortexssh-tui --profile mybox
```

Controls: type normally; `Ctrl+]` quits; mouse wheel / `Shift+PgUp`/`PgDn`
scrolls back; window resize resizes the remote PTY.

---

## 5. GUI — `vortexssh-gui`

Graphical window (`egui`/`eframe`). Same flags as the TUI. Authentication
(password/passphrase prompts and host-key confirmation) happens **inside the
window**, so it can be launched from a desktop menu without a terminal.

```
vortexssh-gui [TARGET] [OPTIONS]
```

```bash
vortexssh-gui user@example.com
vortexssh-gui -i ~/.ssh/id_ed25519 git@github.com
vortexssh-gui --profile mybox
```

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
trust_host_key_blindly = false
```

`auth` methods serialize as `password`, `public_key` (with `key_path`),
`agent`, or `keyboard_interactive`. `forwards` and `trust_host_key_blindly`
are optional and default off.

---

## 7. Core library (`vortexssh-core`) — functions

The engine every front-end uses. No UI/rendering code lives here.

### `config` — persisted profiles

- `Profile { name, host, port, user, auth, forwards, terminal, trust_host_key_blindly }`
- `AuthMethod::{ Password, PublicKey{key_path, use_agent_if_available}, Agent, KeyboardInteractive }`
- `ForwardRule { kind, bind_host, bind_port, dest_host, dest_port }` / `ForwardKind::{ Local, Remote, Dynamic }`
- `TerminalSettings { term_type, scrollback_lines, color_scheme }`
- `ProfileStore` — `new(dir)`, `default_location()`, `list()`, `load(name)`, `save(&profile)`, `delete(name)`

### `keys` — key generation & import/export

- `generate(KeyKind, comment) -> PrivateKey`
- `load_openssh(path, passphrase) -> PrivateKey`
- `save_openssh(&PrivateKey, path)`
- `KeyKind::{ Ed25519, Rsa{bits} }` (RSA min 1024 bits)
- `HashAlg::{ Sha256, ... }` (re-exported)
- `keys::agent` — `connect_env()`, `list_identities(agent)` for `ssh-agent` (`$SSH_AUTH_SOCK`)

### `ssh` — transport & sessions

- `Session::connect(addr, host_label, port, user, auth, verifier) -> Session`
- `Session::open_shell(term_type, cols, rows) -> Channel` (PTY + shell)
- `Session::open_exec(command) -> Channel` (one-shot, no PTY)
- `Session::open_subsystem(name) -> Channel` (e.g. `"sftp"`)
- `Session::disconnect()`
- `AuthCredentials::{ Password(String), PublicKey{key_path, passphrase}, Agent }`
- `HostKeyVerifier` trait — `verify(&self, host, port, key) -> Result<bool>`
- `KnownHosts { prompt }` (TOFU + known_hosts), `AcceptAll` (tests only)
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
- `Error::{ Ssh, Sftp, Key, RusshKey, AgentAuth, Io, Config, HostKeyVerification, AuthFailed, Other }`

---

## 8. Data flow (how the front-ends use the core)

1. Resolve connection settings (CLI args or a `Profile`).
2. Prompt for secrets / confirm the host key (on the terminal).
3. `Session::connect(...)` → `open_shell(term_type, cols, rows)`.
4. Loop: read `ChannelMsg::Data` → `Terminal::feed(&data)` → drain
   `take_responses()` → write back via `channel.data(...)`; send local input
   via `channel.data(...)`; forward resizes via `channel.window_change(...)`.
5. Render by walking `Terminal::viewport_line(i)` and mapping `Cell`/`Attrs` to
   each front-end's styling model (ratatui `Style`, egui `Color32`, …).

The TUI/GUI run the SSH I/O on a background tokio task and keep the `Terminal`
on the UI thread; the CLI drives it directly in an async loop.
