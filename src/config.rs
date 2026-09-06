//! Per-server SSH profiles, loaded from a TOML file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use mcp_toolkit::{ToolFailure, ToolResult};

/// The whole configuration file: a list of server profiles.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, alias = "ssh")]
    pub servers: Vec<SshServerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshServerConfig {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub private_key: Option<PathBuf>,
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Optional pinned host key fingerprint (SHA256).
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Optional SOCKS5 proxy e.g. `<socks5://127.0.0.1:1080>`.
    #[serde(default)]
    pub socks_proxy: Option<String>,
    /// Command regex whitelist (if non-empty, commands must match).
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Command regex blacklist (commands must not match).
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// If true, local paths for upload/download bypass `tools.allowed_roots`.
    #[serde(default)]
    pub bypass_allowed_roots: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl SshServerConfig {
    /// The pinned host key fingerprint in russh's canonical `SHA256:<base64>`
    /// form, accepting a bare base64 digest for convenience.
    ///
    /// Without normalisation a fingerprint written without the `SHA256:` prefix
    /// silently compares unequal, which surfaces to the operator as a host-key
    /// *mismatch* — indistinguishable from an actual attack.
    pub fn normalized_fingerprint(&self) -> Option<String> {
        let raw = self.fingerprint.as_deref()?.trim();
        if raw.is_empty() {
            return None;
        }
        Some(match raw.strip_prefix("SHA256:") {
            Some(digest) => format!("SHA256:{}", digest.trim()),
            None => format!("SHA256:{raw}"),
        })
    }

    /// Whether any authentication method is configured.
    pub fn has_auth_method(&self) -> bool {
        self.private_key.is_some() || self.password.as_deref().is_some_and(|p| !p.is_empty())
    }
}

const fn default_ssh_port() -> u16 {
    22
}

const fn yes() -> bool {
    true
}

impl Config {
    /// Reads and validates a profile file, expanding `${VAR}` in string values
    /// so credentials never have to be written into it.
    pub fn load(path: &std::path::Path) -> ToolResult<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            ToolFailure::InvalidArguments(format!("could not read {}: {e}", path.display()))
        })?;
        let parsed: toml::Value = toml::from_str(&raw).map_err(|e| {
            ToolFailure::InvalidArguments(format!("{} is not valid TOML: {e}", path.display()))
        })?;
        let expanded = expand(parsed)?;
        let config: Self = expanded.try_into().map_err(|e| {
            ToolFailure::InvalidArguments(format!("{} has unusable contents: {e}", path.display()))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Rejects profiles that could never work, at load rather than first use.
    pub fn validate(&self) -> ToolResult<()> {
        let mut seen = std::collections::HashSet::new();
        for server in &self.servers {
            let invalid =
                |msg: String| -> ToolResult<()> { Err(ToolFailure::InvalidArguments(msg)) };

            if server.name.trim().is_empty() {
                invalid("an ssh server profile has an empty name".into())?;
            }
            if !seen.insert(&server.name) {
                invalid(format!("duplicate ssh server name {:?}", server.name))?;
            }
            if server.host.trim().is_empty() {
                invalid(format!("ssh server {:?} has an empty host", server.name))?;
            }
            if server.user.trim().is_empty() {
                invalid(format!("ssh server {:?} has an empty user", server.name))?;
            }

            // An unparseable pattern must not be skipped: for a blacklist that
            // fails open, silently disabling the guard it was written to apply.
            for (kind, patterns) in
                [("whitelist", &server.whitelist), ("blacklist", &server.blacklist)]
            {
                for pattern in patterns {
                    if let Err(err) = regex::Regex::new(pattern) {
                        invalid(format!(
                            "ssh server {:?} has an invalid {kind} pattern {pattern:?}: {err}",
                            server.name
                        ))?;
                    }
                }
            }

            if let Some(raw) =
                server.fingerprint.as_deref().map(str::trim).filter(|f| !f.is_empty())
            {
                let digest = raw.strip_prefix("SHA256:").unwrap_or(raw);
                let plausible = !digest.is_empty()
                    && digest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
                if !plausible {
                    invalid(format!(
                        "ssh server {:?} has fingerprint {raw:?}, which is not a SHA256 digest",
                        server.name
                    ))?;
                }
            }

            if !server.has_auth_method() {
                invalid(format!(
                    "ssh server {:?} has neither `private_key` nor `password`",
                    server.name
                ))?;
            }
        }
        Ok(())
    }
}

/// Expands `${VAR}` and `${VAR:-default}` in every string value.
fn expand(value: toml::Value) -> ToolResult<toml::Value> {
    Ok(match value {
        toml::Value::String(text) => toml::Value::String(expand_str(&text)?),
        toml::Value::Array(items) => {
            toml::Value::Array(items.into_iter().map(expand).collect::<ToolResult<Vec<_>>>()?)
        }
        toml::Value::Table(table) => toml::Value::Table(
            table
                .into_iter()
                .map(|(k, v)| Ok((k, expand(v)?)))
                .collect::<ToolResult<toml::map::Map<_, _>>>()?,
        ),
        other => other,
    })
}

fn expand_str(input: &str) -> ToolResult<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find("${") {
        out.push_str(&rest[..idx]);
        let body = &rest[idx + 2..];
        let Some(end) = body.find('}') else {
            out.push_str("${");
            rest = body;
            continue;
        };
        let (placeholder, tail) = body.split_at(end);
        rest = &tail[1..];

        let (name, default) = match placeholder.split_once(":-") {
            Some((n, d)) => (n.trim(), Some(d)),
            None => (placeholder.trim(), None),
        };
        match std::env::var(name).ok().or_else(|| default.map(String::from)) {
            Some(value) => out.push_str(&value),
            // An unset variable is an error, not an empty credential.
            None => {
                return Err(ToolFailure::InvalidArguments(format!(
                    "config references ${{{name}}} but that environment variable is not set"
                )));
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}
