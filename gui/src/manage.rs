//! In-window management of local SSH keys, trusted `known_hosts` entries and
//! command snippets.
//!
//! Non-UI methods (`generate_key`, `confirm_remove`, etc.) operate on explicit
//! paths so they can be unit-tested against temporary directories without
//! touching the user's `~/.ssh`.

use std::path::PathBuf;

use egui::Color32;
use maelstromssh_core::config::{Snippet, SnippetStore};
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

/// The app-wide management windows, shared by every tab.
#[derive(Default)]
pub struct ToolWindows {
    pub keys: KeysWindow,
    pub known_hosts: KnownHostsWindow,
    pub snippets: SnippetsWindow,
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

/// State for the "Snippets" window: saved commands shared with the web UI.
#[derive(Default)]
pub struct SnippetsWindow {
    pub open: bool,
    /// Where snippets are read and written; `snippets.toml` by default.
    pub store: Option<SnippetStore>,
    pub snippets: Vec<Snippet>,
    /// Name of the snippet being edited; `None` while adding a new one.
    pub editing: Option<String>,
    pub name: String,
    pub command: String,
    pub run: bool,
    /// "Delete" was clicked once for the snippet being edited.
    pub confirm_delete: bool,
    pub status: Option<String>,
    pub error: Option<String>,
}

impl SnippetsWindow {
    /// Opens the window on the default `snippets.toml` (if unset) and reloads it.
    pub fn open(&mut self) {
        self.open = true;
        if self.store.is_none() {
            match SnippetStore::default_location() {
                Ok(store) => self.store = Some(store),
                Err(e) => {
                    self.error = Some(e.to_string());
                    return;
                }
            }
        }
        self.status = None;
        self.refresh();
    }

    /// Reloads the snippet list from the store.
    pub fn refresh(&mut self) {
        if let Some(store) = &self.store {
            match store.list() {
                Ok(list) => {
                    self.snippets = list;
                    self.error = None;
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }

    /// Fills the editor with `name`'s snippet.
    pub fn edit(&mut self, name: &str) {
        if let Some(s) = self.snippets.iter().find(|s| s.name == name) {
            self.editing = Some(s.name.clone());
            self.name = s.name.clone();
            self.command = s.command.clone();
            self.run = s.run;
            self.confirm_delete = false;
            self.status = None;
            self.error = None;
        }
    }

    /// Clears the editor for a new snippet.
    pub fn new_snippet(&mut self) {
        self.editing = None;
        self.name.clear();
        self.command.clear();
        self.run = false;
        self.confirm_delete = false;
    }

    /// Saves the editor's snippet (adding it, or updating the one being edited).
    pub fn save(&mut self) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Err("no snippets file configured".into());
        };
        let snippet = Snippet {
            name: self.name.clone(),
            command: self.command.clone(),
            run: self.run,
        };
        match store.save(snippet, self.editing.as_deref()) {
            Ok(list) => {
                self.snippets = list;
                self.status = Some(format!("Saved '{}'", self.name.trim()));
                self.error = None;
                self.new_snippet();
                Ok(())
            }
            Err(e) => {
                self.error = Some(e.to_string());
                self.status = None;
                Err(e.to_string())
            }
        }
    }

    /// Deletes the snippet being edited.
    pub fn delete(&mut self) -> Result<(), String> {
        let (Some(store), Some(name)) = (&self.store, self.editing.clone()) else {
            return Err("no snippet selected".into());
        };
        match store.delete(&name) {
            Ok(list) => {
                self.snippets = list;
                self.status = Some(format!("Deleted '{name}'"));
                self.error = None;
                self.new_snippet();
                Ok(())
            }
            Err(e) => {
                self.error = Some(e.to_string());
                Err(e.to_string())
            }
        }
    }
}

/// Bytes a snippet sends to the terminal: the command, plus Enter when `run` is set.
pub fn snippet_bytes(snippet: &Snippet) -> Vec<u8> {
    let mut out = snippet.command.clone().into_bytes();
    if snippet.run {
        out.push(b'\r');
    }
    out
}

/// Renders the floating "Snippets" window if open. Returns the bytes to send
/// to the active terminal when a snippet is clicked (only if `can_send`).
pub fn show_snippets_window(
    ctx: &egui::Context,
    window: &mut SnippetsWindow,
    can_send: bool,
) -> Option<Vec<u8>> {
    if !window.open {
        return None;
    }
    let mut send = None;
    let mut open = window.open;
    egui::Window::new("Snippets")
        .open(&mut open)
        .default_size([520.0, 380.0])
        .resizable(true)
        .show(ctx, |ui| {
            if !can_send {
                ui.label("Connect a session to send snippets.");
            }
            let mut to_edit = None;
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    if window.snippets.is_empty() {
                        ui.label("No snippets saved yet. Add one below.");
                    }
                    egui::Grid::new("snippets_grid")
                        .striped(true)
                        .num_columns(3)
                        .spacing([12.0, 6.0])
                        .show(ui, |ui| {
                            for s in &window.snippets {
                                let verb = if s.run { "Run" } else { "Paste" };
                                let btn = ui
                                    .add_enabled(can_send, egui::Button::new(&s.name))
                                    .on_hover_text(format!("{verb}: {}", s.command));
                                if btn.clicked() {
                                    send = Some(snippet_bytes(s));
                                }
                                ui.monospace(&s.command);
                                if ui.small_button("Edit").clicked() {
                                    to_edit = Some(s.name.clone());
                                }
                                ui.end_row();
                            }
                        });
                });
            if let Some(name) = to_edit {
                window.edit(&name);
            }

            ui.separator();
            ui.strong(match &window.editing {
                Some(name) => format!("Edit '{name}'"),
                None => "New snippet".to_string(),
            });
            egui::Grid::new("snippet_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.add(egui::TextEdit::singleline(&mut window.name).desired_width(240.0));
                    ui.end_row();
                    ui.label("Command");
                    ui.add(
                        egui::TextEdit::singleline(&mut window.command)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(240.0),
                    );
                    ui.end_row();
                    ui.label("");
                    ui.checkbox(&mut window.run, "Press Enter after pasting");
                    ui.end_row();
                });
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    let _ = window.save();
                }
                if window.editing.is_some() {
                    if ui.button("New").clicked() {
                        window.new_snippet();
                    }
                    if window.confirm_delete {
                        if ui.button("Confirm delete").clicked() {
                            let _ = window.delete();
                        }
                    } else if ui.button("Delete").clicked() {
                        window.confirm_delete = true;
                    }
                }
            });

            if let Some(err) = &window.error {
                ui.colored_label(ERROR_RED, err.as_str());
            } else if let Some(status) = &window.status {
                ui.colored_label(OK_GREEN, status.as_str());
            }
        });
    window.open = open;
    send
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snippets_window(dir: &std::path::Path) -> SnippetsWindow {
        SnippetsWindow {
            store: Some(SnippetStore::new(dir.join("snippets.toml"))),
            ..SnippetsWindow::default()
        }
    }

    #[test]
    fn snippets_add_edit_delete_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut win = snippets_window(tmp.path());
        win.refresh();
        assert!(win.snippets.is_empty());

        win.name = "disk".into();
        win.command = "df -h".into();
        win.save().unwrap();
        assert_eq!(win.snippets.len(), 1);
        assert!(win.name.is_empty() && win.editing.is_none());

        win.edit("disk");
        win.name = "space".into();
        win.run = true;
        win.save().unwrap();
        assert_eq!(win.snippets.len(), 1);
        assert_eq!(win.snippets[0].name, "space");
        assert!(win.snippets[0].run);

        win.new_snippet();
        win.name = "space".into();
        win.command = "du".into();
        assert!(win.save().unwrap_err().contains("already exists"));

        win.edit("space");
        win.delete().unwrap();
        assert!(win.snippets.is_empty());
        let mut reloaded = snippets_window(tmp.path());
        reloaded.refresh();
        assert!(reloaded.snippets.is_empty());
    }

    #[test]
    fn snippet_bytes_appends_enter_only_when_run() {
        let mut s = Snippet {
            name: "x".into(),
            command: "ls".into(),
            run: false,
        };
        assert_eq!(snippet_bytes(&s), b"ls");
        s.run = true;
        assert_eq!(snippet_bytes(&s), b"ls\r");
    }

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
