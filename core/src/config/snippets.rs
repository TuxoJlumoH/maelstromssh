//! Reusable command snippets saved in `~/.config/maelstromssh/snippets.toml`.

use std::io::ErrorKind;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A saved command snippet that can be pasted or run in an open terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    /// Short label shown in the sidebar, e.g. `"Docker containers"`.
    pub name: String,
    /// Command text sent to the terminal.
    pub command: String,
    /// Whether clicking the snippet sends a trailing Enter (`\r`) right away.
    /// Defaults to `false` (paste only, so the user can review before Enter).
    #[serde(default)]
    pub run: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct SnippetFile {
    #[serde(default)]
    snippets: Vec<Snippet>,
}

/// Reads and writes `snippets.toml`.
pub struct SnippetStore {
    path: PathBuf,
}

impl SnippetStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Uses `$XDG_CONFIG_HOME/maelstromssh/snippets.toml`.
    pub fn default_location() -> Result<Self> {
        let base = dirs::config_dir()
            .ok_or_else(|| Error::Config("could not determine the config directory".into()))?;
        Ok(Self::new(
            crate::paths::app_dir(&base).join("snippets.toml"),
        ))
    }

    pub fn list(&self) -> Result<Vec<Snippet>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::Io(e)),
        };
        let file: SnippetFile = toml::from_str(&text)
            .map_err(|e| Error::Config(format!("parsing {}: {e}", self.path.display())))?;
        Ok(file.snippets)
    }

    /// Saves `snippet` (creating or updating `original_name`) and returns the
    /// sorted list of snippets.
    pub fn save(&self, mut snippet: Snippet, original_name: Option<&str>) -> Result<Vec<Snippet>> {
        snippet.name = snippet.name.trim().to_string();
        snippet.command = snippet.command.trim().to_string();
        if snippet.name.is_empty() || snippet.name.len() > 64 {
            return Err(Error::Config(
                "enter a snippet name (up to 64 characters)".into(),
            ));
        }
        if snippet.command.is_empty() {
            return Err(Error::Config("enter a command".into()));
        }

        let mut list = self.list()?;
        if original_name != Some(snippet.name.as_str())
            && list.iter().any(|s| s.name == snippet.name)
        {
            return Err(Error::Config(format!(
                "a snippet named '{}' already exists",
                snippet.name
            )));
        }

        if let Some(orig) = original_name {
            list.retain(|s| s.name != orig);
        } else {
            list.retain(|s| s.name != snippet.name);
        }
        list.push(snippet);
        list.sort_by(|a, b| a.name.cmp(&b.name));
        self.write_all(&list)?;
        Ok(list)
    }

    pub fn delete(&self, name: &str) -> Result<Vec<Snippet>> {
        let mut list = self.list()?;
        let before = list.len();
        list.retain(|s| s.name != name);
        if list.len() == before {
            return Err(Error::Config(format!("no snippet named '{name}'")));
        }
        self.write_all(&list)?;
        Ok(list)
    }

    fn write_all(&self, snippets: &[Snippet]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = SnippetFile {
            snippets: snippets.to_vec(),
        };
        let text = toml::to_string_pretty(&file)
            .map_err(|e| Error::Config(format!("serializing snippets: {e}")))?;
        std::fs::write(&self.path, text)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_rename_and_delete_snippets() {
        let path = std::env::temp_dir().join(format!(
            "maelstromssh-snippets-{}/snippets.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let store = SnippetStore::new(&path);

        assert!(store.list().unwrap().is_empty());

        let list = store
            .save(
                Snippet {
                    name: "docker-ps".into(),
                    command: "docker ps --format 'table {{.Names}}\\t{{.Status}}'".into(),
                    run: false,
                },
                None,
            )
            .unwrap();
        assert_eq!(list.len(), 1);

        // Duplicate name without original_name fails.
        assert!(store
            .save(
                Snippet {
                    name: "docker-ps".into(),
                    command: "docker ps".into(),
                    run: true,
                },
                None,
            )
            .is_err());

        // Rename and update.
        let list = store
            .save(
                Snippet {
                    name: "containers".into(),
                    command: "docker ps -a".into(),
                    run: true,
                },
                Some("docker-ps"),
            )
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "containers");
        assert!(list[0].run);

        let list = store.delete("containers").unwrap();
        assert!(list.is_empty());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
