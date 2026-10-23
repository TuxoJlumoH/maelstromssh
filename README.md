<p align="center">
  <img src="assets/icon-128.png" width="96" height="96" alt="VortexSSH icon"/>
</p>

<h1 align="center">VortexSSH</h1>

<p align="center">
  An SSH/SFTP client for Linux, written in Rust — use it from the command line, a full-screen
  terminal UI, a desktop window or your web browser, all driven by one shared engine.
</p>

## Features

- **SSH** — works like OpenSSH out of the box: `ssh-agent`, `~/.ssh` keys, password and keyboard-interactive (2FA), `~/.ssh/config` host aliases, and trust-on-first-use host-key verification.
- **SFTP** — scriptable `get`/`put`/`ls`/`rm`/`mkdir`/`rename`, an interactive shell, and a drag-and-drop file browser in the web UI.
- **Port forwarding** — local, remote, and dynamic (SOCKS5 proxy); the web UI adds and stops forwards while connected.
- **Key generation** — Ed25519 and RSA (configurable size).
- **Full terminal emulator** — 256-color + truecolor, scrollback, reflow-on-resize, scroll regions, alternate screen, mouse reporting, bracketed paste.
- **Profiles** — saved connection settings, including port forwards.

## Front-ends

| Binary | What it is |
|---|---|
| `vortexssh` | Command line — connect, `sftp`, `profile`, `keygen` |
| `vortexssh-tui` | Full-screen terminal UI (`ratatui`) |
| `vortexssh-gui` | Desktop window (`egui`/`eframe`) |
| `vortexssh-web` | Browser UI served on 127.0.0.1 (`axum` + `xterm.js`) |

## Install

> **Note:** the web UI (`vortexssh-web`) is newer than the v0.2.0 release. Until the next
> release, build from source to get it.

- **From source** (Rust stable):

  ```bash
  git clone git@github.com:TuxoJlumoH/vortexssh.git
  cd vortexssh
  make                          # cargo build --release
  sudo make install             # /usr/local, with a desktop entry and icons
  # or: make install PREFIX=~/.local
  ```

  `make uninstall` (with the same `PREFIX`) removes it again.
- **Arch / CachyOS**: `cd packaging/aur && makepkg -si` builds the tagged release. It clones
  over SSH, so it needs your GitHub key while the repository is private.
- **Debian / Ubuntu**: download the `.deb` from the
  [releases page](https://github.com/TuxoJlumoH/vortexssh/releases) and run
  `sudo apt install ./vortexssh_*.deb`.
- **Any Linux**: unpack the release tarball and copy its `bin/` and `share/` into
  `/usr/local` or `~/.local`.

## Usage

### Command line

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

### Terminal UI and desktop window

```bash
vortexssh-tui user@host
vortexssh-gui                     # opens a connect form
vortexssh-gui user@host
```

The desktop window asks for passwords, passphrases and host-key confirmation
inside the window, so it also works when started from the app menu.

### Web UI

```bash
vortexssh-web                     # starts the server and opens your browser
vortexssh-web --no-browser        # only print the login link
vortexssh-web --port 9000         # another port (default 8022, or a free one)
```

Each browser tab is one SSH connection with:

- a terminal;
- a file browser — upload (button or drag and drop), download, rename, delete, new folder;
- port forwards you can add and stop while connected.

Saved profiles and your `~/.ssh/config` hosts are listed in the sidebar, and
profiles can be created and edited there. Login prompts appear as dialogs.
Ctrl-C in the terminal where it runs stops the server.

**Security:** the server only accepts connections from this machine, and only
with the random login link it prints at startup (which stops working when the
server stops). Keep the link private. Passwords are never stored.

**From another computer** (e.g. a Mac), tunnel the port over SSH and use the
same port number on both ends:

```bash
ssh -L 8022:127.0.0.1:8022 you@linux-box vortexssh-web --no-browser -p 8022
```

Then open the printed link on that computer. SSH connections still start from
the Linux machine, using its keys and profiles, and forwards open ports there.

## Project layout

```
core/    vortexssh-core — protocol engine (SSH, SFTP, tunnel, keys, terminal)
cli/     vortexssh      — command line
tui/     vortexssh-tui  — ratatui terminal UI
gui/     vortexssh-gui  — egui/eframe desktop window
web/     vortexssh-web  — browser UI (axum server + plain JS, xterm.js vendored)
assets/                 — app icon (SVG/PNG)
packaging/              — desktop entry, Arch PKGBUILD
```

## Documentation

Full usage and API reference: [`HELP.md`](HELP.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

The web UI bundles [xterm.js](https://xtermjs.org) and its fit addon, both
under the MIT license; see `web/assets/vendor/`.
