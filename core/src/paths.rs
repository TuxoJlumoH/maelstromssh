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
    fn collapses_home_prefix() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(collapse_home(&home.join(".ssh/id_rsa")), "~/.ssh/id_rsa");
        assert_eq!(collapse_home(Path::new("/etc/hosts")), "/etc/hosts");
    }
}
