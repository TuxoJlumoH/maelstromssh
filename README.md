<p align="center">
  <img src="assets/icon-128.png" width="96" height="96" alt="VortexSSH icon"/>
</p>

<h1 align="center">VortexSSH</h1>

<p align="center">
  An SSH/SFTP client for Linux, written in Rust — with a CLI, a terminal TUI, and a graphical
  GUI, all driven by one UI-agnostic engine.
</p>

## Features

- **SSH** — password, public-key, and `ssh-agent` authentication, with trust-on-first-use host-key verification.
- **SFTP** — scriptable `get`/`put`/`ls`/`rm`/`mkdir`/`rename`, plus an interactive shell.
- **Port forwarding** — local, remote, and dynamic (SOCKS5 proxy).
- **Key generation** — Ed25519 and RSA (configurable size).
- **Full terminal emulator** — 256-color + truecolor, scrollback, reflow-on-resize, scroll regions, alternate screen, mouse reporting, bracketed paste.
- **Profiles** — persisted connection settings (with per-profile port forwards).

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
vortexssh connect user@host                       # agent, ~/.ssh keys, then password
vortexssh connect -i ~/.ssh/id_ed25519 git@github.com
vortexssh connect myalias                         # Host alias from ~/.ssh/config
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

## Project layout

```
core/    vortexssh-core — protocol engine (SSH, SFTP, tunnel, keys, terminal)
cli/     vortexssh      — command-line front-end
tui/     vortexssh-tui  — ratatui terminal UI
gui/     vortexssh-gui  — egui/eframe graphical UI
assets/                 — app icon (SVG/PNG)
```

## Documentation

Full usage and API reference: [`HELP.md`](HELP.md).

## License

No license has been chosen yet.
