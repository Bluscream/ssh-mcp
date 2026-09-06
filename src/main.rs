//! ssh-mcp — SSH command execution, SFTP transfer and host telemetry over MCP.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use mcp_toolkit::ServerOptions;

use ssh_mcp::config::Config;
use ssh_mcp::policy::Policy;
use ssh_mcp::tools::SshTools;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-mcp",
    version,
    about = "SSH execution, SFTP transfer and host telemetry as an MCP server"
)]
struct Cli {
    #[command(flatten)]
    server: ServerOptions,

    /// TOML file of server profiles. `${VAR}` in values is read from the
    /// environment, so credentials need not be written into it.
    #[arg(long, short = 'c', env = "SSH_MCP_CONFIG")]
    config: PathBuf,

    /// Permit downloads to write to this machine.
    #[arg(long, env = "SSH_MCP_ALLOW_DOWNLOAD")]
    allow_download: bool,

    /// Confine local transfer paths to this directory. Repeatable.
    #[arg(long = "root", value_name = "DIR", env = "SSH_MCP_ROOT")]
    roots: Vec<PathBuf>,

    /// Permit overwriting a MISMATCHED host key. A mismatch is either a key
    /// rotation or an active man-in-the-middle; leave this off unless you
    /// intend to make that call.
    #[arg(long, env = "SSH_MCP_ALLOW_HOST_KEY_OVERRIDE")]
    allow_host_key_override: bool,

    /// Refuse to connect to hosts absent from `known_hosts`, instead of recording
    /// them on first sight.
    #[arg(long, env = "SSH_MCP_STRICT_HOST_KEYS")]
    strict_host_keys: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("ssh-mcp: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let policy = Policy::new(
        cli.allow_download,
        cli.allow_host_key_override,
        !cli.strict_host_keys,
        &cli.roots,
    );
    let group = Arc::new(SshTools::new(config.servers, policy));

    match mcp_toolkit::run("ssh", env!("CARGO_PKG_VERSION"), group, cli.server).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssh-mcp: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
