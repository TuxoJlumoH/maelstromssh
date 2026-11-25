//! In-window management of local SSH keys and trusted `known_hosts` entries.
//!
//! Non-UI methods (`generate_key`, `confirm_remove`, etc.) operate on explicit
//! paths so they can be unit-tested against temporary directories without
//! touching the user's `~/.ssh`.

use std::path::PathBuf;

use egui::Color32;
use maelstromssh_core::keys::{
    KeyKind, PublicKeyInfo, default_ssh_dir, generate_in_dir, list_ssh_keys,
};
use maelstromssh_core::paths::collapse_home;
use maelstromssh_core::ssh::{
    KnownHostEntry, default_known_hosts_path, list_known_hosts, remove_known_host_line,
};

const ERROR_RED: Color32 = Color32::from_rgb(240, 80, 80);
const OK_GREEN: Color32 = Color32::from_rgb(90, 210, 120);

/// Supported key algorithms for generation in the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyTypeChoice {
    #[default]
    Ed25519,
    Rsa3072,
}

impl KeyTypeChoice {
    /// Returns the standard default file name for this key type.
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::Rsa3072 => "id_rsa",
        }
    }
}

/// State for the "SSH keys" management window.
#[derive(Debug)]
pub struct KeysWindow {
    pub open: bool,
    /// Target directory for listing and generating keys (e.g. `~/.ssh`).
    pub dir: Option<PathBuf>,
    pub keys: Vec<PublicKeyInfo>,
    pub key_type: KeyTypeChoice,
    pub file_name: String,
    pub comment: String,
    pub status: Option<String>,
    pub error: Option<String>,
}

impl Default for KeysWindow {
    fn default() -> Self {
        Self {
            open: false,
            dir: None,
            keys: Vec::new(),
            key_type: KeyTypeChoice::Ed25519,
            file_name: KeyTypeChoice::Ed25519.default_filename().to_string(),
            comment: String::new(),
            status: None,
            error: None,
        }
    }
}

impl KeysWindow {
    /// Opens the window, populating the default SSH directory if unset, and reloads keys.
    pub fn open(&mut self) {
        self.open = true;
        if self.dir.is_none() {
            match default_ssh_dir() {
                Ok(d) => self.dir = Some(d),
                Err(e) => {
                    self.error = Some(e.to_string());
                    return;
                }
            }
        }
        self.error = None;
        self.status = None;
        self.refresh();
    }

    /// Sets the key type, updating the default filename if the user has not customized it.
    pub fn set_key_type(&mut self, new_type: KeyTypeChoice) {
        if self.key_type != new_type {
            let old_default = self.key_type.default_filename();
            if self.file_name.trim() == old_default {
                self.file_name = new_type.default_filename().to_string();
            }
            self.key_type = new_type;
        }
    }

    /// Reloads the list of public keys from the configured directory.
    pub fn refresh(&mut self) {
        if let Some(ref dir) = self.dir {
            match list_ssh_keys(dir) {
                Ok(keys) => {
                    self.keys = keys;
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(e.to_string());
                }
            }
        }
    }

    /// Generates a new keypair in the configured directory, refreshing the list on success.
    pub fn generate_key(&mut self) -> Result<PublicKeyInfo, String> {
        let Some(ref dir) = self.dir else {
            let err = "no SSH directory configured".to_string();
            self.error = Some(err.clone());
            return Err(err);
        };
        // RSA 3072 key generation involves finding large primes and can take ~1s.
        let kind = match self.key_type {
            KeyTypeChoice::Ed25519 => KeyKind::Ed25519,
            KeyTypeChoice::Rsa3072 => KeyKind::Rsa { bits: 3072 },
        };
        match generate_in_dir(dir, &self.file_name, kind, self.comment.trim()) {
            Ok(info) => {
                self.error = None;
                self.status = Some(format!("Generated {}", info.private_path));
                self.refresh();
                Ok(info)
            }
            Err(e) => {
                let msg = e.to_string();
                self.error = Some(msg.clone());
                self.status = None;
                Err(msg)
            }
        }
    }
}

/// State for the "Known hosts" management window.
#[derive(Debug, Default)]
pub struct KnownHostsWindow {
    pub open: bool,
    /// Path to the `known_hosts` file being managed.
    pub path: Option<PathBuf>,
    pub entries: Vec<KnownHostEntry>,
    /// Line number currently awaiting user confirmation before deletion.
    pub confirm_remove: Option<usize>,
    pub error: Option<String>,
}

impl KnownHostsWindow {
    /// Opens the window, populating the default `known_hosts` path if unset, and reloads entries.
    pub fn open(&mut self) {
        self.open = true;
        if self.path.is_none() {
            match default_known_hosts_path() {
                Ok(p) => self.path = Some(p),
                Err(e) => {
                    self.error = Some(e.to_string());
                    return;
                }
            }
        }
        self.confirm_remove = None;
        self.error = None;
        self.refresh();
    }

    /// Reloads the list of known hosts from disk.
    pub fn refresh(&mut self) {
        if let Some(ref path) = self.path {
            match list_known_hosts(path) {
                Ok(entries) => {
                    self.entries = entries;
                    self.error = None;
                }
                Err(e) => {
                    self.error = Some(e.to_string());
                }
            }
        }
    }

    /// Sets the line number pending removal confirmation.
    pub fn request_remove(&mut self, line: usize) {
        self.confirm_remove = Some(line);
    }

    /// Cancels any pending removal confirmation.
    pub fn cancel_remove(&mut self) {
        self.confirm_remove = None;
    }

    /// Removes the specified line if it matches the current confirmation state.
    pub fn confirm_remove(&mut self, line: usize) -> Result<bool, String> {
        if self.confirm_remove != Some(line) {
            return Ok(false);
        }
        self.confirm_remove = None;
        let Some(ref path) = self.path else {
            let err = "no known_hosts path configured".to_string();
            self.error = Some(err.clone());
            return Err(err);
        };
        match remove_known_host_line(path, line) {
            Ok(removed) => {
                self.error = None;
                self.refresh();
                Ok(removed)
            }
            Err(e) => {
                let msg = e.to_string();
                self.error = Some(msg.clone());
                Err(msg)
            }
        }
    }
}

/// Renders the floating "SSH keys" window if open.
pub fn show_keys_window(ctx: &egui::Context, window: &mut KeysWindow) {
    if !window.open {
        return;
    }
    let mut open = window.open;
    egui::Window::new("SSH keys")
        .open(&mut open)
        .default_size([580.0, 400.0])
        .resizable(true)
        .show(ctx, |ui| {
            let dir_display = match &window.dir {
                Some(d) => collapse_home(d),
                None => "~/.ssh".to_string(),
            };
            ui.horizontal(|ui| {
                ui.label(format!("Directory: {dir_display}"));
                if ui.button("Refresh").clicked() {
                    window.refresh();
                }
            });

            ui.separator();

            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    if window.keys.is_empty() {
                        ui.label("No public keys in ~/.ssh yet. Generate one below.");
                    } else {
                        egui::Grid::new("keys_grid")
                            .striped(true)
                            .num_columns(4)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.strong("File");
                                ui.strong("Type");
                                ui.strong("Fingerprint");
                                ui.label("");
                                ui.end_row();

                                for key in &window.keys {
                                    ui.label(&key.name);
                                    ui.label(&key.algorithm);
                                    ui.monospace(&key.fingerprint);
                                    if ui.small_button("Copy public key").clicked() {
                                        ui.ctx().copy_text(key.openssh.clone());
                                    }
                                    ui.end_row();
                                }
                            });
                    }
                });

            ui.separator();

            ui.heading("Generate a new keypair");
            egui::Grid::new("keygen_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Type");
                    let mut selected = window.key_type;
                    egui::ComboBox::from_id_salt("key_type_combo")
                        .selected_text(match selected {
                            KeyTypeChoice::Ed25519 => "Ed25519",
                            KeyTypeChoice::Rsa3072 => "RSA (3072-bit)",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut selected, KeyTypeChoice::Ed25519, "Ed25519");
                            ui.selectable_value(
                                &mut selected,
                                KeyTypeChoice::Rsa3072,
                                "RSA (3072-bit)",
                            );
                        });
                    if selected != window.key_type {
                        window.set_key_type(selected);
                    }
                    ui.end_row();

                    ui.label("File name");
                    ui.add(
                        egui::TextEdit::singleline(&mut window.file_name)
                            .hint_text("id_ed25519")
                            .desired_width(180.0),
                    );
                    ui.end_row();

                    ui.label("Comment");
                    ui.add(
                        egui::TextEdit::singleline(&mut window.comment)
                            .hint_text("optional, e.g. user@laptop")
                            .desired_width(180.0),
                    );
                    ui.end_row();
                });

            ui.add_space(4.0);
            if ui.button("Generate key").clicked() {
                let _ = window.generate_key();
            }

            if let Some(err) = &window.error {
                ui.add_space(4.0);
                ui.colored_label(ERROR_RED, err.as_str());
            } else if let Some(status) = &window.status {
                ui.add_space(4.0);
                ui.colored_label(OK_GREEN, status.as_str());
            }
        });
    window.open = open;
}

/// Renders the floating "Known hosts" window if open.
pub fn show_known_hosts_window(ctx: &egui::Context, window: &mut KnownHostsWindow) {
    if !window.open {
        return;
    }
    let mut open = window.open;
    egui::Window::new("Known hosts")
        .open(&mut open)
        .default_size([640.0, 360.0])
        .resizable(true)
        .show(ctx, |ui| {
            let path_display = match &window.path {
                Some(p) => collapse_home(p),
                None => "~/.ssh/known_hosts".to_string(),
            };
            ui.horizontal(|ui| {
                ui.label(format!("File: {path_display}"));
                if ui.button("Refresh").clicked() {
                    window.confirm_remove = None;
                    window.refresh();
                }
            });

            ui.separator();

            egui::ScrollArea::vertical()
                .max_height(260.0)
                .show(ui, |ui| {
                    if window.entries.is_empty() {
                        ui.label("No trusted server keys saved yet.");
                    } else {
                        egui::Grid::new("known_hosts_grid")
                            .striped(true)
                            .num_columns(4)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.strong("Host");
                                ui.strong("Key type");
                                ui.strong("Fingerprint");
                                ui.label("");
                                ui.end_row();

                                let mut to_confirm = None;
                                let mut to_cancel = false;
                                let mut to_request = None;

                                for entry in &window.entries {
                                    ui.label(&entry.hosts);
                                    ui.label(&entry.algorithm);
                                    ui.monospace(&entry.fingerprint);
                                    if window.confirm_remove == Some(entry.line) {
                                        ui.horizontal(|ui| {
                                            if ui.small_button("Confirm remove").clicked() {
                                                to_confirm = Some(entry.line);
                                            }
                                            if ui.small_button("Cancel").clicked() {
                                                to_cancel = true;
                                            }
                                        });
                                    } else if ui.small_button("Remove").clicked() {
                                        to_request = Some(entry.line);
                                    }
                                    ui.end_row();
                                }

                                if let Some(line) = to_confirm {
                                    let _ = window.confirm_remove(line);
                                } else if to_cancel {
                                    window.cancel_remove();
                                } else if let Some(line) = to_request {
                                    window.request_remove(line);
                                }
                            });
                    }
                });

            if let Some(err) = &window.error {
                ui.add_space(4.0);
                ui.colored_label(ERROR_RED, err.as_str());
            }
        });
    window.open = open;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn key_type_choice_default_filename_switching() {
        let mut win = KeysWindow::default();
        assert_eq!(win.key_type, KeyTypeChoice::Ed25519);
        assert_eq!(win.file_name, "id_ed25519");

        // Switching to RSA switches default name to id_rsa
        win.set_key_type(KeyTypeChoice::Rsa3072);
        assert_eq!(win.key_type, KeyTypeChoice::Rsa3072);
        assert_eq!(win.file_name, "id_rsa");

        // Switching back switches to id_ed25519
        win.set_key_type(KeyTypeChoice::Ed25519);
        assert_eq!(win.key_type, KeyTypeChoice::Ed25519);
        assert_eq!(win.file_name, "id_ed25519");

        // Custom name is preserved across type switches
        win.file_name = "my_custom_key".to_string();
        win.set_key_type(KeyTypeChoice::Rsa3072);
        assert_eq!(win.file_name, "my_custom_key");
        win.set_key_type(KeyTypeChoice::Ed25519);
        assert_eq!(win.file_name, "my_custom_key");
    }

    #[test]
    fn generate_key_in_temp_dir() {
        let temp = tempfile::tempdir().unwrap();
        let mut win = KeysWindow {
            dir: Some(temp.path().to_path_buf()),
            comment: "test-user@box".to_string(),
            ..Default::default()
        };

        win.refresh();
        assert!(win.keys.is_empty());

        let res = win.generate_key();
        assert!(res.is_ok());
        let info = res.unwrap();
        assert_eq!(info.name, "id_ed25519");
        assert_eq!(info.comment, "test-user@box");
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert!(info.fingerprint.starts_with("SHA256:"));

        // Window state updated
        assert_eq!(win.keys.len(), 1);
        assert_eq!(win.keys[0].name, "id_ed25519");
        assert!(win.status.is_some());
        assert!(win.error.is_none());

        // Files exist on disk
        assert!(temp.path().join("id_ed25519").exists());
        assert!(temp.path().join("id_ed25519.pub").exists());

        // Generating again with same name fails and does not duplicate
        let res2 = win.generate_key();
        assert!(res2.is_err());
        assert!(win.error.is_some());
        assert_eq!(win.keys.len(), 1);
    }

    #[test]
    fn known_hosts_confirmation_and_remove() {
        let temp = tempfile::tempdir().unwrap();
        let kh_path = temp.path().join("known_hosts");

        let text = format!(
            "# comment line\n\
             web-01.example.com {SAMPLE_KEY} deploy@web-01\n\
             db-01.example.com {SAMPLE_KEY}\n\
             test-01.example.com {SAMPLE_KEY}\n"
        );
        std::fs::write(&kh_path, text).unwrap();

        let mut win = KnownHostsWindow {
            path: Some(kh_path.clone()),
            ..Default::default()
        };

        win.refresh();
        assert_eq!(win.entries.len(), 3);
        assert_eq!(win.entries[0].line, 2);
        assert_eq!(win.entries[0].hosts, "web-01.example.com");
        assert_eq!(win.entries[1].line, 3);
        assert_eq!(win.entries[1].hosts, "db-01.example.com");
        assert_eq!(win.entries[2].line, 4);
        assert_eq!(win.entries[2].hosts, "test-01.example.com");

        // Attempting to remove line 2 without confirmation fails
        let removed = win.confirm_remove(2).unwrap();
        assert!(!removed);
        assert_eq!(win.entries.len(), 3);

        // Requesting confirmation sets state
        win.request_remove(2);
        assert_eq!(win.confirm_remove, Some(2));

        // Canceling clears confirmation
        win.cancel_remove();
        assert_eq!(win.confirm_remove, None);

        // Request remove line 2, but confirm line 3 -> rejected
        win.request_remove(2);
        let removed = win.confirm_remove(3).unwrap();
        assert!(!removed);
        assert_eq!(win.entries.len(), 3);

        // Proper confirmation removes line 2 and refreshes
        win.request_remove(2);
        let removed = win.confirm_remove(2).unwrap();
        assert!(removed);
        assert_eq!(win.confirm_remove, None);
        assert_eq!(win.entries.len(), 2);

        // Lines shift: db-01 is now on line 2, test-01 on line 3
        assert_eq!(win.entries[0].hosts, "db-01.example.com");
        assert_eq!(win.entries[0].line, 2);
        assert_eq!(win.entries[1].hosts, "test-01.example.com");
        assert_eq!(win.entries[1].line, 3);

        // Verify comment preserved in file
        let content = std::fs::read_to_string(&kh_path).unwrap();
        assert!(content.starts_with("# comment line\n"));
        assert!(!content.contains("web-01.example.com"));
        assert!(content.contains("db-01.example.com"));
    }
}
