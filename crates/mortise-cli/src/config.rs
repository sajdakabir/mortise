//! `.mortise.toml`: which project and environment a directory uses.
//!
//! ```toml
//! project = "api"
//! environment = "dev"
//! ```
//!
//! Found by walking up from the working directory, so `mortise run` works
//! from anywhere inside the repository. Holds names only — never a secret —
//! so it is safe to commit.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The file this looks for.
pub const FILE_NAME: &str = ".mortise.toml";

/// Defaults for `mortise run` in a directory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
// Unknown keys are refused: `enviroment = "prod"` silently falling back to a
// different environment is the kind of typo that ships the wrong secrets.
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Project name.
    pub project: Option<String>,
    /// Environment name.
    pub environment: Option<String>,
}

/// The nearest `.mortise.toml` at or above `start`, parsed.
///
/// `Ok(None)` when there is none. A file that exists but does not parse is an
/// error, not a reason to keep looking further up.
pub fn find(start: &Path) -> Result<Option<(PathBuf, Config)>, String> {
    for dir in start.ancestors() {
        let path = dir.join(FILE_NAME);
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        let config = toml::from_str(&text)
            .map_err(|e| format!("{} is not valid: {}", path.display(), e.message()))?;
        return Ok(Some((path, config)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nearest_file_wins_and_parent_files_are_ignored() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(root.path().join(FILE_NAME), "project = \"outer\"\n").unwrap();
        std::fs::write(
            root.path().join("a").join(FILE_NAME),
            "project = \"inner\"\nenvironment = \"dev\"\n",
        )
        .unwrap();

        let (path, config) = find(&nested).unwrap().unwrap();
        assert_eq!(path, root.path().join("a").join(FILE_NAME));
        assert_eq!(config.project.as_deref(), Some("inner"));
        assert_eq!(config.environment.as_deref(), Some("dev"));
    }

    #[test]
    fn a_misspelled_key_is_an_error_not_a_silent_default() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(FILE_NAME),
            "project = \"api\"\nenviroment = \"prod\"\n",
        )
        .unwrap();
        let err = find(root.path()).unwrap_err();
        assert!(err.contains("enviroment"), "{err}");
    }
}
