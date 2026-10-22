use std::path::PathBuf;

use crate::error::{Error, Result};

use super::Profile;

/// Reads/writes profiles as individual TOML files under a profiles directory
/// (default: `~/.config/vortexssh/profiles/<name>.toml`).
pub struct ProfileStore {
    dir: PathBuf,
}

impl ProfileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Uses `$XDG_CONFIG_HOME/vortexssh/profiles` (default `~/.config/...`).
    pub fn default_location() -> Result<Self> {
        let base = dirs::config_dir()
            .ok_or_else(|| Error::Config("could not determine the config directory".into()))?;
        Ok(Self::new(base.join("vortexssh").join("profiles")))
    }

    pub fn list(&self) -> Result<Vec<String>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn load(&self, name: &str) -> Result<Profile> {
        let path = self.profile_path(name);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            Error::Config(match e.kind() {
                std::io::ErrorKind::NotFound => {
                    format!("no profile named '{name}' (see `vortexssh profile list`)")
                }
                _ => format!("reading {}: {e}", path.display()),
            })
        })?;
        toml::from_str(&text).map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))
    }

    pub fn save(&self, profile: &Profile) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.profile_path(&profile.name);
        let text = toml::to_string_pretty(profile)
            .map_err(|e| Error::Config(format!("serializing profile: {e}")))?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        std::fs::remove_file(self.profile_path(name))?;
        Ok(())
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.toml"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, Profile};

    #[test]
    fn save_and_load_roundtrip() {
        let tmp = tempdir();
        let store = ProfileStore::new(&tmp);
        let profile = Profile {
            name: "test-host".into(),
            host: "example.com".into(),
            port: 22,
            user: "alice".into(),
            auth: AuthMethod::Password,
            forwards: vec![],
            terminal: Default::default(),
        };
        store.save(&profile).unwrap();
        let loaded = store.load("test-host").unwrap();
        assert_eq!(loaded.host, "example.com");
        assert_eq!(loaded.user, "alice");

        let names = store.list().unwrap();
        assert_eq!(names, vec!["test-host".to_string()]);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn loads_profiles_with_removed_fields() {
        let tmp = tempdir().with_extension("legacy");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("old.toml"),
            "name = \"old\"\nhost = \"h\"\nuser = \"u\"\ntrust_host_key_blindly = false\n\
             auth = { method = \"public_key\", key_path = \"/k\", use_agent_if_available = true }\n",
        )
        .unwrap();
        let p = ProfileStore::new(&tmp).load("old").unwrap();
        assert_eq!(p.port, 22);
        std::fs::remove_dir_all(&tmp).ok();
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("vortexssh-test-{}", std::process::id()));
        p
    }
}
