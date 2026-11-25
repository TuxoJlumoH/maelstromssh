# Changelog

## Unreleased

### Added

- Desktop window: *SSH keys* (list, copy, generate) and *Known hosts* (view, remove) windows.

## 0.5.0 — 2026-11-25

### Added

- Jump hosts: `-J [user@]host[:port][,...]` and `ProxyJump` from
  `~/.ssh/config`, in profiles and in every front-end.
- Terminal UI and desktop window: serial ports, Telnet, raw TCP and session
  logging (`--log`, or *Save output* in the desktop window's connect form).
- Terminal UI and desktop window: SFTP file browser and port forwards
  (`-L`/`-R`/`-D`), added and stopped while connected (`F12` in the terminal
  UI, *Files (SFTP)* / *Forwards* in the desktop window).
- Known-hosts manager: `maelstromssh known-hosts list|remove`, and a
  *Known hosts* dialog in the web UI. Failed connections show troubleshooting
  hints.
- Web UI: SSH key list and key generator.
- Web UI: command snippets in the sidebar (`snippets.toml`).

### Changed

- Rust 2024 edition; dependencies upgraded (russh 0.65, egui/eframe 0.37,
  ratatui 0.30, crossterm 0.29, toml 1).
- Desktop window: `Ctrl+Shift+V` pastes, like `Ctrl+V`.
- CI runs `cargo audit`.

### Security

- russh 0.65.4 fixes RUSTSEC-2026-0495 (agent server ignored
  confirm-before-use constraints).
- rsa 0.10.0 fixes RUSTSEC-2023-0071 (Marvin timing side channel).
- url 2.5.9 fixes RUSTSEC-2026-0592.

### Removed

- The one-time migration of old `vortexssh` folders.

## 0.4.0 — 2026-10-24

- Renamed from VortexSSH to MaelstromSSH; `mssh` alias.
