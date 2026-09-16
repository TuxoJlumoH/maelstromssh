<p align="center">
  <img src="assets/icon.png" width="96" height="96" alt="VortexSSH icon"/>
</p>

<h1 align="center">VortexSSH</h1>

<p align="center">
  An SSH/SFTP client in Rust — with a CLI, a terminal TUI, and a graphical
  GUI, all driven by one UI-agnostic engine.
</p>

## Features

- **SSH** — password, public-key, and `ssh-agent` authentication (Unix `$SSH_AUTH_SOCK` and the Windows OpenSSH named pipe), with trust-on-first-use host-key verification.
- **SFTP** — scriptable `get`/`put`/`ls`/`rm`/`mkdir`/`rename`, plus an interactive shell.
- **Port forwarding** — local, remote, and dynamic (SOCKS5 proxy).
- **Key generation** — Ed25519 and RSA (configurable size).
- **Full terminal emulator** — 256-color + truecolor, scrollback, reflow-on-resize, scroll regions, alternate screen, mouse reporting, bracketed paste.
- **Profiles** — persisted connection settings (with per-profile port forwards).
- **Windows** — cross-compiled `.exe`s, an installer, and a windowed GUI (no console).

## Getting started

```bash
git clone git@github.com:TuxoJlumoH/vortexssh.git
cd vortexssh
cargo build --release
```

Three binaries are produced:

| Binary | Description |
|---|---|
| `vortexssh` | CLI — connect, `sftp`, `profile`, `keygen` |
| `vortexssh-tui` | Full-screen terminal UI (`ratatui`) |
| `vortexssh-gui` | Graphical window (`egui`/`eframe`) |

### CLI

```bash
vortexssh connect user@host                       # password auth (prompted)
vortexssh connect -i ~/.ssh/id_ed25519 git@github.com
vortexssh connect -L 8080:localhost:80 user@host  # local forward
vortexssh connect -D 1080 user@host               # SOCKS5 proxy
vortexssh sftp user@host                          # interactive SFTP shell
vortexssh keygen -t ed25519                       # generate a key
vortexssh profile add mybox user@host -p 2222
```

### TUI / GUI

```bash
vortexssh-tui user@host
vortexssh-gui user@host
```

The GUI performs authentication (password/passphrase prompts and host-key
confirmation) inside the window.

## Windows

The engine and all three front-ends cross-compile to `x86_64-pc-windows-gnu`:

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

Installers (NSIS and Inno Setup) live in [`installer/windows/`](installer/windows/);
a GitHub Actions workflow (`.github/workflows/windows-installer.yml`) builds the
native installer on a `v*` tag.

## Project layout

```
core/    vortexssh-core — protocol engine (SSH, SFTP, tunnel, keys, terminal)
cli/     vortexssh      — command-line front-end
tui/     vortexssh-tui  — ratatui terminal UI
gui/     vortexssh-gui  — egui/eframe graphical UI
installer/              — NSIS + Inno Setup Windows installers
assets/                 — app icon (SVG/ICO/PNG)
```

## Documentation

Full usage and API reference: [`HELP.md`](HELP.md).

## License

No license has been chosen yet.
