//! Local path helpers.

use std::path::{Path, PathBuf};

/// Expands a leading `~` or `~/` to the home directory. Anything else
/// (including `~user`) is returned unchanged.
pub fn expand_tilde(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let Ok(rest) = path.strip_prefix("~") else {
        return path.to_path_buf();
    };
    match dirs::home_dir() {
        Some(home) => home.join(rest),
        None => path.to_path_buf(),
    }
}

/// The app's folder name under the XDG config/data directories.
pub const APP_DIR: &str = "maelstromssh";

/// The folder name used before the rename from VortexSSH.
const OLD_APP_DIR: &str = "vortexssh";

/// Returns `base/maelstromssh`. If only the pre-rename `base/vortexssh`
/// exists, it is moved there first so profiles and logs carry over.
pub fn app_dir(base: &Path) -> PathBuf {
    let new = base.join(APP_DIR);
    let old = base.join(OLD_APP_DIR);
    if !new.exists() && old.is_dir() {
        match std::fs::rename(&old, &new) {
            Ok(()) => eprintln!(
                "moved {} to {} (VortexSSH is now MaelstromSSH)",
                collapse_home(&old),
                collapse_home(&new)
            ),
            Err(e) => eprintln!("could not move {}: {e}", collapse_home(&old)),
        }
    }
    new
}

/// Shows a path with the home directory as `~`, for messages and prompts.
pub fn collapse_home(path: &Path) -> String {
    match dirs::home_dir().and_then(|home| path.strip_prefix(home).ok().map(Path::to_path_buf)) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_home_prefix_only() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~"), home);
        assert_eq!(
            expand_tilde("~/.ssh/id_ed25519"),
            home.join(".ssh/id_ed25519")
        );
        assert_eq!(expand_tilde("/etc/~"), PathBuf::from("/etc/~"));
        assert_eq!(expand_tilde("~bob/x"), PathBuf::from("~bob/x"));
        assert_eq!(expand_tilde("rel/path"), PathBuf::from("rel/path"));
    }

    #[test]
    fn app_dir_moves_the_old_folder_once() {
        let base = std::env::temp_dir().join(format!("maelstromssh-appdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("vortexssh/profiles")).unwrap();
        std::fs::write(base.join("vortexssh/profiles/a.toml"), "x").unwrap();

        let dir = app_dir(&base);
        assert_eq!(dir, base.join("maelstromssh"));
        assert!(dir.join("profiles/a.toml").exists());
        assert!(!base.join("vortexssh").exists());

        // An old folder that reappears never overwrites the new one.
        std::fs::create_dir_all(base.join("vortexssh")).unwrap();
        app_dir(&base);
        assert!(base.join("vortexssh").exists());
        assert!(dir.join("profiles/a.toml").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn collapses_home_prefix() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(collapse_home(&home.join(".ssh/id_rsa")), "~/.ssh/id_rsa");
        assert_eq!(collapse_home(Path::new("/etc/hosts")), "/etc/hosts");
    }
}
