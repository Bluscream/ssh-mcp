//! What this server is allowed to do.

use std::path::{Component, Path, PathBuf};

use mcp_toolkit::{ToolFailure, ToolResult};

#[derive(Debug, Clone)]
pub struct Policy {
    allow_transfer_write: bool,
    allow_host_key_override: bool,
    allow_host_key_learning: bool,
    roots: Vec<PathBuf>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_transfer_write: false,
            allow_host_key_override: false,
            allow_host_key_learning: true,
            roots: Vec::new(),
        }
    }
}

impl Policy {
    pub fn new(
        allow_transfer_write: bool,
        allow_host_key_override: bool,
        allow_host_key_learning: bool,
        roots: &[PathBuf],
    ) -> Self {
        let roots = roots.iter().map(|r| r.canonicalize().unwrap_or_else(|_| r.clone())).collect();
        Self { allow_transfer_write, allow_host_key_override, allow_host_key_learning, roots }
    }

    pub fn allows_host_key_learning(&self) -> bool {
        self.allow_host_key_learning
    }

    pub fn allows_host_key_override(&self) -> bool {
        self.allow_host_key_override
    }

    /// Fails unless writing to the local filesystem was enabled.
    pub fn require_write(&self) -> ToolResult<()> {
        if self.allow_transfer_write {
            return Ok(());
        }
        Err(ToolFailure::Denied(
            "downloading writes to this machine, which is disabled; start the server with \
             --allow-download to permit it"
                .into(),
        ))
    }

    /// Fails unless overriding a *mismatched* host key was enabled.
    ///
    /// A fingerprint mismatch is either a legitimate key rotation or an active
    /// man-in-the-middle. Telling them apart needs out-of-band knowledge a
    /// model does not have, so this stays a human decision.
    pub fn require_host_key_override(&self) -> ToolResult<()> {
        if self.allow_host_key_override {
            return Ok(());
        }
        Err(ToolFailure::Denied(
            "refusing to overwrite a mismatched SSH host key. This is a decision for a human: \
             verify the new key out of band, then either update ~/.ssh/known_hosts yourself or \
             restart the server with --allow-host-key-override"
                .into(),
        ))
    }

    /// Resolves a local path, rejecting anything outside the configured roots.
    pub fn resolve(&self, raw: &str) -> ToolResult<PathBuf> {
        if raw.trim().is_empty() {
            return Err(ToolFailure::InvalidArguments("path must not be empty".into()));
        }
        let requested = Path::new(raw);
        if requested.is_relative() {
            return Err(ToolFailure::InvalidArguments(format!(
                "local path {raw:?} must be absolute"
            )));
        }
        let resolved = requested.canonicalize().unwrap_or_else(|_| normalize(requested));
        if self.roots.is_empty() || self.roots.iter().any(|root| resolved.starts_with(root)) {
            return Ok(resolved);
        }
        Err(ToolFailure::Denied(format!("local path {raw:?} is outside the configured --root set")))
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_and_key_override_are_denied_by_default() {
        let policy = Policy::default();
        assert!(matches!(policy.require_write(), Err(ToolFailure::Denied(_))));
        assert!(matches!(policy.require_host_key_override(), Err(ToolFailure::Denied(_))));
    }

    #[test]
    fn host_key_learning_is_on_by_default() {
        // Matches OpenSSH's StrictHostKeyChecking=accept-new.
        assert!(Policy::default().allows_host_key_learning());
        assert!(!Policy::new(false, false, false, &[]).allows_host_key_learning());
    }

    #[test]
    fn the_override_denial_says_it_is_a_human_decision() {
        let err = Policy::default().require_host_key_override().unwrap_err();
        assert!(err.to_string().contains("decision for a human"), "{err}");
    }

    #[test]
    fn capabilities_are_granted_once_enabled() {
        let policy = Policy::new(true, true, true, &[]);
        assert!(policy.require_write().is_ok());
        assert!(policy.require_host_key_override().is_ok());
    }

    #[test]
    fn local_paths_are_confined_to_the_roots() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let policy = Policy::new(true, false, true, std::slice::from_ref(&root));

        assert!(policy.resolve(root.join("f").to_str().unwrap()).is_ok());
        assert!(matches!(policy.resolve("/etc/passwd"), Err(ToolFailure::Denied(_))));
        assert!(policy.resolve("relative").is_err());
    }
}
